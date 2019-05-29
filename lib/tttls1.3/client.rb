# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  using Refinements

  module ClientState
    # initial value is 0, eof value is -1
    START         = 1
    WAIT_SH       = 2
    WAIT_EE       = 3
    WAIT_CERT_CR  = 4
    WAIT_CERT     = 5
    WAIT_CV       = 6
    WAIT_FINISHED = 7
    CONNECTED     = 8
  end

  DEFAULT_CH_CIPHER_SUITES = [
    CipherSuite::TLS_AES_256_GCM_SHA384,
    CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
    CipherSuite::TLS_AES_128_GCM_SHA256
  ].freeze
  private_constant :DEFAULT_CH_CIPHER_SUITES

  DEFAULT_CH_SIGNATURE_ALGORITHMS = [
    SignatureScheme::ECDSA_SECP256R1_SHA256,
    SignatureScheme::ECDSA_SECP384R1_SHA384,
    SignatureScheme::ECDSA_SECP521R1_SHA512,
    SignatureScheme::RSA_PSS_RSAE_SHA256,
    SignatureScheme::RSA_PSS_RSAE_SHA384,
    SignatureScheme::RSA_PSS_RSAE_SHA512,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA512
  ].freeze
  private_constant :DEFAULT_CH_SIGNATURE_ALGORITHMS

  DEFAULT_CH_NAMED_GROUP_LIST = [
    NamedGroup::SECP256R1,
    NamedGroup::SECP384R1,
    NamedGroup::SECP521R1
  ].freeze
  private_constant :DEFAULT_CH_NAMED_GROUP_LIST

  DEFAULT_CLIENT_SETTINGS = {
    ca_file: nil,
    cipher_suites: DEFAULT_CH_CIPHER_SUITES,
    signature_algorithms: DEFAULT_CH_SIGNATURE_ALGORITHMS,
    signature_algorithms_cert: nil,
    supported_groups: DEFAULT_CH_NAMED_GROUP_LIST,
    key_share_groups: nil,
    process_new_session_ticket: nil,
    ticket: nil,
    resumption_master_secret: nil,
    psk_cipher_suite: nil,
    ticket_nonce: nil,
    ticket_age_add: nil,
    ticket_timestamp: nil,
    loglevel: Logger::WARN
  }.freeze
  private_constant :DEFAULT_CLIENT_SETTINGS

  # rubocop: disable Metrics/ClassLength
  class Client < Connection
    # @param socket [Socket]
    # @param hostname [String]
    # @param settings [Hash]
    def initialize(socket, hostname, **settings)
      super(socket)

      @endpoint = :client
      @hostname = hostname
      @settings = DEFAULT_CLIENT_SETTINGS.merge(settings)
      logger.level = @settings[:loglevel]

      @early_data = ''
      @succeed_early_data = false
      raise Error::ConfigError unless valid_settings?
    end

    # NOTE:
    #                           START <----+
    #            Send ClientHello |        | Recv HelloRetryRequest
    #       [K_send = early data] |        |
    #                             v        |
    #        /                 WAIT_SH ----+
    #        |                    | Recv ServerHello
    #        |                    | K_recv = handshake
    #    Can |                    V
    #   send |                 WAIT_EE
    #  early |                    | Recv EncryptedExtensions
    #   data |           +--------+--------+
    #        |     Using |                 | Using certificate
    #        |       PSK |                 v
    #        |           |            WAIT_CERT_CR
    #        |           |        Recv |       | Recv CertificateRequest
    #        |           | Certificate |       v
    #        |           |             |    WAIT_CERT
    #        |           |             |       | Recv Certificate
    #        |           |             v       v
    #        |           |              WAIT_CV
    #        |           |                 | Recv CertificateVerify
    #        |           +> WAIT_FINISHED <+
    #        |                  | Recv Finished
    #        \                  | [Send EndOfEarlyData]
    #                           | K_send = handshake
    #                           | [Send Certificate [+ CertificateVerify]]
    # Can send                  | Send Finished
    # app data   -->            | K_send = K_recv = application
    # after here                v
    #                       CONNECTED
    #
    # https://tools.ietf.org/html/rfc8446#appendix-A.1
    #
    # rubocop: disable Metrics/AbcSize
    # rubocop: disable Metrics/BlockLength
    # rubocop: disable Metrics/CyclomaticComplexity
    # rubocop: disable Metrics/MethodLength
    # rubocop: disable Metrics/PerceivedComplexity
    def connect
      transcript = Transcript.new
      key_schedule = nil # TTTLS13::KeySchedule
      psk = nil
      priv_keys = {} # Hash of NamedGroup => OpenSSL::PKey::$Object
      if use_psk?
        psk = gen_psk_from_nst(
          @settings[:resumption_master_secret],
          @settings[:ticket_nonce],
          CipherSuite.digest(@settings[:psk_cipher_suite])
        )
        key_schedule = KeySchedule.new(
          psk: psk,
          shared_secret: nil,
          cipher_suite: @settings[:psk_cipher_suite],
          transcript: transcript
        )
      end
      hs_wcipher = nil # TTTLS13::Cryptograph::$Object
      hs_rcipher = nil # TTTLS13::Cryptograph::$Object
      e_wcipher = nil # TTTLS13::Cryptograph::$Object

      @state = ClientState::START
      loop do
        case @state
        when ClientState::START
          logger.debug('ClientState::START')

          extensions, priv_keys = gen_ch_extensions
          binder_key = (use_psk? ? key_schedule.binder_key_res : nil)
          transcript[CH] = send_client_hello(extensions, binder_key)

          send_ccs # compatibility mode
          if use_early_data?
            e_wcipher = gen_cipher(
              @settings[:psk_cipher_suite],
              key_schedule.early_data_write_key,
              key_schedule.early_data_write_iv
            )
            send_early_data(e_wcipher)
          end

          @state = ClientState::WAIT_SH
        when ClientState::WAIT_SH
          logger.debug('ClientState::WAIT_SH')

          sh = transcript[SH] = recv_server_hello

          # support only TLS 1.3
          terminate(:protocol_version) unless sh.negotiated_tls_1_3?

          # validate parameters
          terminate(:illegal_parameter) unless sh.appearable_extensions?
          terminate(:illegal_parameter) if sh.downgraded?
          terminate(:illegal_parameter) \
            unless sh.legacy_compression_method == "\x00"

          # validate sh using ch
          ch = transcript[CH]
          terminate(:illegal_parameter) \
            unless sh.legacy_version == ch.legacy_version
          terminate(:illegal_parameter) \
            unless sh.legacy_session_id_echo == ch.legacy_session_id
          terminate(:illegal_parameter) \
            unless ch.cipher_suites.include?(sh.cipher_suite)
          terminate(:unsupported_extension) \
            unless (sh.extensions.keys - ch.extensions.keys).empty?

          # validate sh using hrr
          if transcript.include?(HRR)
            hrr = transcript[HRR]
            terminate(:illegal_parameter) \
              unless sh.cipher_suite == hrr.cipher_suite

            sh_sv = sh.extensions[Message::ExtensionType::SUPPORTED_VERSIONS]
            hrr_sv = hrr.extensions[Message::ExtensionType::SUPPORTED_VERSIONS]
            terminate(:illegal_parameter) \
              unless sh_sv.versions == hrr_sv.versions
          end

          # handling HRR
          if sh.hrr?
            terminate(:unexpected_message) if transcript.include?(HRR)
            ch1 = transcript[CH1] = transcript.delete(CH)
            hrr = transcript[HRR] = transcript.delete(SH)

            # validate cookie
            diff_sets = sh.extensions.keys - ch1.extensions.keys
            terminate(:unsupported_extension) \
              unless (diff_sets - [Message::ExtensionType::COOKIE]).empty?

            # validate key_share
            # TODO: pre_shared_key
            ngl = ch1.extensions[Message::ExtensionType::SUPPORTED_GROUPS]
                     .named_group_list
            kse = ch1.extensions[Message::ExtensionType::KEY_SHARE]
                     .key_share_entry
            group = hrr.extensions[Message::ExtensionType::KEY_SHARE]
                       .key_share_entry.first.group
            terminate(:illegal_parameter) \
              unless ngl.include?(group) && !kse.map(&:group).include?(group)

            # send new client_hello
            extensions, pk = gen_newch_extensions(ch1, hrr)
            priv_keys = pk.merge(priv_keys)
            transcript[CH] = send_new_client_hello(ch1, extensions)
            @state = ClientState::WAIT_SH
            next
          end

          # generate shared secret
          psk = nil unless sh.extensions
                             .include?(Message::ExtensionType::PRE_SHARED_KEY)
          ch_ks = ch.extensions[Message::ExtensionType::KEY_SHARE]
                    .key_share_entry.map(&:group)
          sh_ks = sh.extensions[Message::ExtensionType::KEY_SHARE]
                    .key_share_entry.first.group
          terminate(:illegal_parameter) unless ch_ks.include?(sh_ks)

          kse = sh.extensions[Message::ExtensionType::KEY_SHARE]
                  .key_share_entry.first
          ke = kse.key_exchange
          @named_group = kse.group
          priv_key = priv_keys[@named_group]
          shared_secret = gen_shared_secret(ke, priv_key, @named_group)
          @cipher_suite = sh.cipher_suite
          key_schedule = KeySchedule.new(
            psk: psk,
            shared_secret: shared_secret,
            cipher_suite: @cipher_suite,
            transcript: transcript
          )
          @alert_wcipher = hs_wcipher = gen_cipher(
            @cipher_suite,
            key_schedule.client_handshake_write_key,
            key_schedule.client_handshake_write_iv
          )
          hs_rcipher = gen_cipher(
            @cipher_suite,
            key_schedule.server_handshake_write_key,
            key_schedule.server_handshake_write_iv
          )
          @state = ClientState::WAIT_EE
        when ClientState::WAIT_EE
          logger.debug('ClientState::WAIT_EE')

          ee = transcript[EE] = recv_encrypted_extensions(hs_rcipher)
          terminate(:illegal_parameter) unless ee.appearable_extensions?

          ch = transcript[CH]
          terminate(:unsupported_extension) \
            unless (ee.extensions.keys - ch.extensions.keys).empty?

          rsl = ee.extensions[Message::ExtensionType::RECORD_SIZE_LIMIT]
          @send_record_size = rsl.record_size_limit unless rsl.nil?

          @succeed_early_data = true \
            if ee.extensions.include?(Message::ExtensionType::EARLY_DATA)

          @state = ClientState::WAIT_CERT_CR
          @state = ClientState::WAIT_FINISHED unless psk.nil?
        when ClientState::WAIT_CERT_CR
          logger.debug('ClientState::WAIT_EE')

          message = recv_message(receivable_ccs: true, cipher: hs_rcipher)
          if message.msg_type == Message::HandshakeType::CERTIFICATE
            ct = transcript[CT] = message
            terminate(:illegal_parameter) unless ct.appearable_extensions?

            ch = transcript[CH]
            terminate(:unsupported_extension) \
              unless ct.certificate_list.map(&:extensions)
                       .all? { |e| (e.keys - ch.extensions.keys).empty? }

            terminate(:certificate_unknown) \
              unless trusted_certificate?(ct.certificate_list,
                                          @settings[:ca_file], @hostname)

            @state = ClientState::WAIT_CV
          elsif message.msg_type == Message::HandshakeType::CERTIFICATE_REQUEST
            transcript[CR] = message
            # TODO: client authentication
            @state = ClientState::WAIT_CERT
          else
            terminate(:unexpected_message)
          end
        when ClientState::WAIT_CERT
          logger.debug('ClientState::WAIT_EE')

          ct = transcript[CT] = recv_certificate(hs_rcipher)
          terminate(:illegal_parameter) unless ct.appearable_extensions?

          ch = transcript[CH]
          terminate(:unsupported_extension) \
            unless ct.certificate_list.map(&:extensions)
                     .all? { |e| (e.keys - ch.extensions.keys).empty? }

          terminate(:certificate_unknown) \
            unless trusted_certificate?(ct.certificate_list,
                                        @settings[:ca_file], @hostname)

          @state = ClientState::WAIT_CV
        when ClientState::WAIT_CV
          logger.debug('ClientState::WAIT_EE')

          cv = transcript[CV] = recv_certificate_verify(hs_rcipher)
          digest = CipherSuite.digest(@cipher_suite)
          hash = transcript.hash(digest, CT)
          terminate(:decrypt_error) \
            unless verified_certificate_verify?(transcript[CT], cv, hash)

          @signature_scheme = cv.signature_scheme

          @state = ClientState::WAIT_FINISHED
        when ClientState::WAIT_FINISHED
          logger.debug('ClientState::WAIT_EE')

          sf = transcript[SF] = recv_finished(hs_rcipher)
          digest = CipherSuite.digest(@cipher_suite)
          verified = verified_finished?(
            finished: sf,
            digest: digest,
            finished_key: key_schedule.server_finished_key,
            hash: transcript.hash(digest, CV)
          )
          terminate(:decrypt_error) unless verified

          transcript[EOED] = send_eoed(e_wcipher) \
            if use_early_data? && succeed_early_data?

          # TODO: Send Certificate [+ CertificateVerify]
          signature = sign_finished(
            digest: digest,
            finished_key: key_schedule.client_finished_key,
            hash: transcript.hash(digest, EOED)
          )
          transcript[CF] = send_finished(signature, hs_wcipher)
          @alert_wcipher = @ap_wcipher = gen_cipher(
            @cipher_suite,
            key_schedule.client_application_write_key,
            key_schedule.client_application_write_iv
          )
          @ap_rcipher = gen_cipher(
            @cipher_suite,
            key_schedule.server_application_write_key,
            key_schedule.server_application_write_iv
          )
          @resumption_master_secret = key_schedule.resumption_master_secret
          @state = ClientState::CONNECTED
        when ClientState::CONNECTED
          logger.debug('ClientState::CONNECTED')

          break
        end
      end
    end
    # rubocop: enable Metrics/AbcSize
    # rubocop: enable Metrics/BlockLength
    # rubocop: enable Metrics/CyclomaticComplexity
    # rubocop: enable Metrics/MethodLength
    # rubocop: enable Metrics/PerceivedComplexity

    # @param binary [String]
    #
    # @raise [TTTLS13::Error::ConfigError]
    def early_data(binary)
      raise Error::ConfigError unless @state == INITIAL && use_psk?

      @early_data = binary
    end

    # @return [Boolean]
    def succeed_early_data?
      @succeed_early_data
    end

    private

    # @return [Boolean]
    # rubocop: disable Metrics/CyclomaticComplexity
    # rubocop: disable Metrics/PerceivedComplexity
    def valid_settings?
      mod = CipherSuite
      defined_cipher_suites = mod.constants.map { |c| mod.const_get(c) }
      return false \
        unless (@settings[:cipher_suites] - defined_cipher_suites).empty?

      sa = @settings[:signature_algorithms]
      mod = SignatureScheme
      defined_signature_schemes = mod.constants.map { |c| mod.const_get(c) }
      return false unless (sa - defined_signature_schemes).empty?

      sac = @settings[:signature_algorithms_cert] || []
      return false unless (sac - defined_signature_schemes).empty?

      sg = @settings[:supported_groups]
      return false unless (sac - defined_signature_schemes).empty?

      ksg = @settings[:key_share_groups]
      return false \
        unless ksg.nil? ||
               ((ksg - sg).empty? && sg.select { |g| ksg.include?(g) } == ksg)

      true
    end
    # rubocop: enable Metrics/CyclomaticComplexity
    # rubocop: enable Metrics/PerceivedComplexity

    # @return [Boolean]
    def use_psk?
      !@settings[:ticket].nil? &&
        !@settings[:resumption_master_secret].nil? &&
        !@settings[:psk_cipher_suite].nil? &&
        !@settings[:ticket_nonce].nil? &&
        !@settings[:ticket_age_add].nil? &&
        !@settings[:ticket_timestamp].nil?
    end

    # @return [Boolean]
    def use_early_data?
      !(@early_data.nil? || @early_data.empty?)
    end

    # @param cipher [TTTLS13::Cryptograph::Aead]
    def send_early_data(cipher)
      ap = Message::ApplicationData.new(@early_data)
      ap_record = Message::Record.new(
        type: Message::ContentType::APPLICATION_DATA,
        legacy_record_version: Message::ProtocolVersion::TLS_1_2,
        messages: [ap],
        cipher: cipher
      )
      send_record(ap_record)
    end

    # @param resumption_master_secret [String]
    # @param ticket_nonce [String]
    # @param digest [String] name of digest algorithm
    #
    # @return [String]
    def gen_psk_from_nst(resumption_master_secret, ticket_nonce, digest)
      hash_len = OpenSSL::Digest.new(digest).digest_length
      info = hash_len.to_uint16
      info += 'tls13 resumption'.prefix_uint8_length
      info += ticket_nonce.prefix_uint8_length
      KeySchedule.hkdf_expand(resumption_master_secret, info, hash_len, digest)
    end

    # @return [TTTLS13::Message::Extensions]
    # @return [Hash of NamedGroup => OpenSSL::PKey::EC.$Object]
    # rubocop: disable Metrics/AbcSize
    # rubocop: disable Metrics/CyclomaticComplexity
    def gen_ch_extensions
      exs = []
      # supported_versions: only TLS 1.3
      exs << Message::Extension::SupportedVersions.new(
        msg_type: Message::HandshakeType::CLIENT_HELLO
      )

      # signature_algorithms
      exs << Message::Extension::SignatureAlgorithms.new(
        @settings[:signature_algorithms]
      )

      # signature_algorithms_cert
      if !@settings[:signature_algorithms_cert].nil? &&
         !@settings[:signature_algorithms_cert].empty?
        exs << Message::Extension::SignatureAlgorithmsCert.new(
          @settings[:signature_algorithms_cert]
        )
      end

      # supported_groups
      groups = @settings[:supported_groups]
      exs << Message::Extension::SupportedGroups.new(groups)

      # key_share
      ksg = @settings[:key_share_groups] || groups
      key_share, priv_keys \
                 = Message::Extension::KeyShare.gen_ch_key_share(ksg)
      exs << key_share

      # server_name
      exs << Message::Extension::ServerName.new(@hostname) \
        if !@hostname.nil? && !@hostname.empty?

      # early_data
      exs << Message::Extension::EarlyDataIndication.new if use_early_data?

      [Message::Extensions.new(exs), priv_keys]
    end
    # rubocop: enable Metrics/AbcSize
    # rubocop: enable Metrics/CyclomaticComplexity

    # @param extensions [TTTLS13::Message::Extensions]
    # @param binder_key [String, nil]
    #
    # @return [TTTLS13::Message::ClientHello]
    def send_client_hello(extensions, binder_key = nil)
      ch = Message::ClientHello.new(
        cipher_suites: CipherSuites.new(@settings[:cipher_suites]),
        extensions: extensions
      )

      if use_psk?
        # pre_shared_key && psk_key_exchange_modes
        #
        # In order to use PSKs, clients MUST also send a
        # "psk_key_exchange_modes" extension.
        #
        # https://tools.ietf.org/html/rfc8446#section-4.2.9
        pkem = Message::Extension::PskKeyExchangeModes.new(
          [Message::Extension::PskKeyExchangeMode::PSK_DHE_KE]
        )
        ch.extensions[Message::ExtensionType::PSK_KEY_EXCHANGE_MODES] = pkem
        # at the end, sign PSK binder
        sign_psk_binder(
          ch: ch,
          binder_key: binder_key
        )
      end

      send_handshakes(Message::ContentType::HANDSHAKE, [ch],
                      Cryptograph::Passer.new)

      ch
    end

    # @param ch1 [TTTLS13::Message::ClientHello]
    # @param hrr [TTTLS13::Message::ServerHello]
    # @param ch [TTTLS13::Message::ClientHello]
    # @param binder_key [String]
    #
    # @return [String]
    def sign_psk_binder(ch1: nil, hrr: nil, ch:, binder_key:)
      # pre_shared_key
      #
      # binder is computed as an HMAC over a transcript hash containing a
      # partial ClientHello up to and including the
      # PreSharedKeyExtension.identities field.
      #
      # https://tools.ietf.org/html/rfc8446#section-4.2.11.2
      digest = CipherSuite.digest(@settings[:psk_cipher_suite])
      hash_len = OpenSSL::Digest.new(digest).digest_length
      dummy_binders = ["\x00" * hash_len]
      psk = Message::Extension::PreSharedKey.new(
        msg_type: Message::HandshakeType::CLIENT_HELLO,
        offered_psks: Message::Extension::OfferedPsks.new(
          identities: [Message::Extension::PskIdentity.new(
            identity: @settings[:ticket],
            obfuscated_ticket_age: calc_obfuscated_ticket_age
          )],
          binders: dummy_binders
        )
      )
      ch.extensions[Message::ExtensionType::PRE_SHARED_KEY] = psk

      psk.offered_psks.binders[0] = do_sign_psk_binder(
        ch1: ch1,
        hrr: hrr,
        ch: ch,
        binder_key: binder_key,
        digest: digest
      )
    end

    # @return [Integer]
    def calc_obfuscated_ticket_age
      # the "ticket_lifetime" field in the NewSessionTicket message is
      # in seconds but the "obfuscated_ticket_age" is in milliseconds.
      age = (Time.now.to_f * 1000).to_i - @settings[:ticket_timestamp] * 1000
      (age + Convert.bin2i(@settings[:ticket_age_add])) % (2**32)
    end

    # @param ch1 [TTTLS13::Message::ClientHello]
    # @param hrr [TTTLS13::Message::ServerHello]
    #
    # @return [TTTLS13::Message::Extensions]
    # @return [Hash of NamedGroup => OpenSSL::PKey::EC.$Object]
    def gen_newch_extensions(ch1, hrr)
      exs = []
      # key_share
      if hrr.extensions.include?(Message::ExtensionType::KEY_SHARE)
        group = hrr.extensions[Message::ExtensionType::KEY_SHARE]
                   .key_share_entry.first.group
        key_share, priv_keys \
                   = Message::Extension::KeyShare.gen_ch_key_share([group])
        exs << key_share
      end

      # cookie
      #
      # When sending a HelloRetryRequest, the server MAY provide a "cookie"
      # extension to the client. When sending the new ClientHello, the client
      # MUST copy the contents of the extension received in the
      # HelloRetryRequest into a "cookie" extension in the new ClientHello.
      #
      # https://tools.ietf.org/html/rfc8446#section-4.2.2
      exs << hrr.extensions[Message::ExtensionType::COOKIE] \
        if hrr.extensions.include?(Message::ExtensionType::COOKIE)

      # early_data
      new_exs = ch1.extensions.merge(Message::Extensions.new(exs))
      new_exs.delete(Message::ExtensionType::EARLY_DATA)

      [new_exs, priv_keys]
    end

    # NOTE:
    # https://tools.ietf.org/html/rfc8446#section-4.1.2
    #
    # @param ch1 [TTTLS13::Message::ClientHello]
    # @param extensions [TTTLS13::Message::Extensions]
    #
    # @return [TTTLS13::Message::ClientHello]
    def send_new_client_hello(ch1, extensions)
      ch = Message::ClientHello.new(
        legacy_version: ch1.legacy_version,
        random: ch1.random,
        legacy_session_id: ch1.legacy_session_id,
        cipher_suites: ch1.cipher_suites,
        legacy_compression_methods: ch1.legacy_compression_methods,
        extensions: extensions
      )
      send_handshakes(Message::ContentType::HANDSHAKE, [ch],
                      Cryptograph::Passer.new)

      ch
    end

    # @raise [TTTLS13::Error::ErrorAlerts]
    #
    # @return [TTTLS13::Message::ServerHello]
    def recv_server_hello
      sh = recv_message(receivable_ccs: true, cipher: Cryptograph::Passer.new)
      terminate(:unexpected_message) unless sh.is_a?(Message::ServerHello)

      sh
    end

    # @param cipher [TTTLS13::Cryptograph::Aead]
    #
    # @raise [TTTLS13::Error::ErrorAlerts]
    #
    # @return [TTTLS13::Message::EncryptedExtensions]
    def recv_encrypted_extensions(cipher)
      ee = recv_message(receivable_ccs: true, cipher: cipher)
      terminate(:unexpected_message) \
        unless ee.is_a?(Message::EncryptedExtensions)

      ee
    end

    # @param cipher [TTTLS13::Cryptograph::Aead]
    #
    # @raise [TTTLS13::Error::ErrorAlerts]
    #
    # @return [TTTLS13::Message::Certificate]
    def recv_certificate(cipher)
      ct = recv_message(receivable_ccs: true, cipher: cipher)
      terminate(:unexpected_message) unless ct.is_a?(Message::Certificate)

      ct
    end

    # @param cipher [TTTLS13::Cryptograph::Aead]
    #
    # @raise [TTTLS13::Error::ErrorAlerts]
    #
    # @return [TTTLS13::Message::CertificateVerify]
    def recv_certificate_verify(cipher)
      cv = recv_message(receivable_ccs: true, cipher: cipher)
      terminate(:unexpected_message) unless cv.is_a?(Message::CertificateVerify)

      cv
    end

    # @param cipher [TTTLS13::Cryptograph::Aead]
    #
    # @raise [TTTLS13::Error::ErrorAlerts]
    #
    # @return [TTTLS13::Message::Finished]
    def recv_finished(cipher)
      sf = recv_message(receivable_ccs: true, cipher: cipher)
      terminate(:unexpected_message) unless sf.is_a?(Message::Finished)

      sf
    end

    # @param cipher [TTTLS13::Cryptograph::Aead]
    #
    # @return [TTTLS13::Message::Finished]
    def send_finished(signature, cipher)
      cf = Message::Finished.new(signature)
      send_handshakes(Message::ContentType::APPLICATION_DATA, [cf], cipher)

      cf
    end

    # @param cipher [TTTLS13::Cryptograph::Aead]
    #
    # @return [TTTLS13::Message::EndOfEarlyData]
    def send_eoed(cipher)
      eoed = Message::EndOfEarlyData.new
      send_handshakes(Message::ContentType::APPLICATION_DATA, [eoed], cipher)

      eoed
    end

    # @param ct [TTTLS13::Message::Certificate]
    # @param cv [TTTLS13::Message::CertificateVerify]
    # @param hash [String]
    #
    # @return [Boolean]
    def verified_certificate_verify?(ct, cv, hash)
      public_key = ct.certificate_list.first.cert_data.public_key
      signature_scheme = cv.signature_scheme
      signature = cv.signature

      do_verified_certificate_verify?(
        public_key: public_key,
        signature_scheme: signature_scheme,
        signature: signature,
        context: 'TLS 1.3, server CertificateVerify',
        hash: hash
      )
    end

    # @param nst [TTTLS13::Message::NewSessionTicket]
    #
    # @raise [TTTLS13::Error::ErrorAlerts]
    def process_new_session_ticket(nst)
      super(nst)

      rms = @resumption_master_secret
      cs = @cipher_suite
      @settings[:process_new_session_ticket]&.call(nst, rms, cs)
    end
  end
  # rubocop: enable Metrics/ClassLength
end
