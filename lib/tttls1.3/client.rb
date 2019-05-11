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

  DEFAULT_CH_SIGNATURE_ALGORITHMS = [
    SignatureScheme::ECDSA_SECP256R1_SHA256,
    SignatureScheme::ECDSA_SECP384R1_SHA384,
    SignatureScheme::ECDSA_SECP521R1_SHA512,
    SignatureScheme::RSA_PSS_PSS_SHA256,
    SignatureScheme::RSA_PSS_PSS_SHA384,
    SignatureScheme::RSA_PSS_PSS_SHA512,
    SignatureScheme::RSA_PSS_RSAE_SHA256,
    SignatureScheme::RSA_PSS_RSAE_SHA384,
    SignatureScheme::RSA_PSS_RSAE_SHA512,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA512
  ].freeze

  DEFAULT_CH_NAMED_GROUP_LIST = [
    Message::Extension::NamedGroup::SECP256R1,
    Message::Extension::NamedGroup::SECP384R1,
    Message::Extension::NamedGroup::SECP521R1
  ].freeze

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
      @early_data_write_cipher = nil # Cryptograph::$Object
      @accepted_early_data = false
      raise Error::ConfigError unless valid_settings?
      return unless use_psk?

      digest = CipherSuite.digest(@settings[:psk_cipher_suite])
      @psk = gen_psk_from_nst(@settings[:resumption_master_secret],
                              @settings[:ticket_nonce], digest)
      @key_schedule = KeySchedule.new(
        psk: @psk,
        shared_secret: nil,
        cipher_suite: @settings[:psk_cipher_suite],
        transcript: @transcript
      )
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
      @state = ClientState::START
      loop do
        case @state
        when ClientState::START
          logger.debug('ClientState::START')

          @transcript[CH] = send_client_hello
          if use_early_data?
            @early_data_write_cipher \
            = gen_cipher(@settings[:psk_cipher_suite],
                         @key_schedule.early_data_write_key,
                         @key_schedule.early_data_write_iv)
            send_early_data
          end

          @state = ClientState::WAIT_SH
        when ClientState::WAIT_SH
          logger.debug('ClientState::WAIT_SH')

          sh = @transcript[SH] = recv_server_hello
          # support only TLS 1.3
          terminate(:protocol_version) unless negotiated_tls_1_3?

          # validate parameters
          terminate(:illegal_parameter) unless valid_sh_legacy_version?
          terminate(:illegal_parameter) unless valid_sh_random?
          terminate(:illegal_parameter) unless valid_sh_legacy_session_id_echo?
          terminate(:illegal_parameter) unless valid_sh_cipher_suite?
          terminate(:illegal_parameter) \
            if @transcript.include?(HRR) &&
               neq_hrr_cipher_suite?(sh.cipher_suite)
          terminate(:illegal_parameter) unless valid_sh_compression_method?

          # handling HRR
          if sh.hrr?
            terminate(:unexpected_message) if received_2nd_hrr?

            @transcript[CH1] = @transcript.delete(CH)
            @transcript[HRR] = @transcript.delete(SH)
            terminate(:unsupported_extension) \
              unless offered_ch_extensions?(sh.extensions, HRR)
            terminate(:illegal_parameter) unless valid_hrr_key_share?

            ch = send_new_client_hello(@transcript[CH1], @transcript[HRR])
            @transcript[CH] = ch
            @state = ClientState::WAIT_SH
            next
          end

          # validate extensions
          terminate(:unsupported_extension) \
            unless offered_ch_extensions?(sh.extensions)

          versions \
          = sh.extensions[Message::ExtensionType::SUPPORTED_VERSIONS].versions
          terminate(:illegal_parameter) \
            if @transcript.include?(HRR) &&
               neq_hrr_supported_versions?(versions)

          # generate shared secret
          @psk = nil unless sh.extensions
                              .include?(Message::ExtensionType::PRE_SHARED_KEY)
          terminate(:illegal_parameter) unless valid_sh_key_share?

          kse = sh.extensions[Message::ExtensionType::KEY_SHARE]
                  .key_share_entry.first
          ke = kse.key_exchange
          group = kse.group
          priv_key = @priv_keys[group]
          shared_secret = gen_shared_secret(ke, priv_key, group)
          @cipher_suite = sh.cipher_suite
          @key_schedule = KeySchedule.new(psk: @psk,
                                          shared_secret: shared_secret,
                                          cipher_suite: @cipher_suite,
                                          transcript: @transcript)
          @write_cipher = gen_cipher(@cipher_suite,
                                     @key_schedule.client_handshake_write_key,
                                     @key_schedule.client_handshake_write_iv)
          @read_cipher = gen_cipher(@cipher_suite,
                                    @key_schedule.server_handshake_write_key,
                                    @key_schedule.server_handshake_write_iv)
          @state = ClientState::WAIT_EE
        when ClientState::WAIT_EE
          logger.debug('ClientState::WAIT_EE')

          ee = @transcript[EE] = recv_encrypted_extensions
          terminate(:illegal_parameter) if ee.any_forbidden_extensions?
          terminate(:unsupported_extension) \
            unless offered_ch_extensions?(ee.extensions)

          rsl = ee.extensions[Message::ExtensionType::RECORD_SIZE_LIMIT]
          @send_record_size = rsl.record_size_limit unless rsl.nil?

          @accepted_early_data = true \
            if ee.extensions.include?(Message::ExtensionType::EARLY_DATA)

          @state = ClientState::WAIT_CERT_CR
          @state = ClientState::WAIT_FINISHED unless @psk.nil?
        when ClientState::WAIT_CERT_CR
          logger.debug('ClientState::WAIT_EE')

          message = recv_message
          if message.msg_type == Message::HandshakeType::CERTIFICATE
            ct = @transcript[CT] = message
            terminate(:unsupported_extension) \
              unless ct.certificate_list.map(&:extensions)
                       .all? { |ex| offered_ch_extensions?(ex) }

            terminate(:certificate_unknown) \
              unless certified_certificate?(ct.certificate_list,
                                            @settings[:ca_file], @hostname)

            @state = ClientState::WAIT_CV
          elsif message.msg_type == Message::HandshakeType::CERTIFICATE_REQUEST
            @transcript[CR] = message
            # TODO: client authentication
            @state = ClientState::WAIT_CERT
          else
            terminate(:unexpected_message)
          end
        when ClientState::WAIT_CERT
          logger.debug('ClientState::WAIT_EE')

          ct = @transcript[CT] = recv_certificate
          terminate(:unsupported_extension) \
            unless ct.certificate_list.map(&:extensions)
                     .all? { |ex| offered_ch_extensions?(ex) }

          terminate(:certificate_unknown) \
            unless certified_certificate?(ct.certificate_list,
                                          @settings[:ca_file], @hostname)

          @state = ClientState::WAIT_CV
        when ClientState::WAIT_CV
          logger.debug('ClientState::WAIT_EE')

          @transcript[CV] = recv_certificate_verify
          terminate(:decrypt_error) unless verify_certificate_verify
          @state = ClientState::WAIT_FINISHED
        when ClientState::WAIT_FINISHED
          logger.debug('ClientState::WAIT_EE')

          @transcript[SF] = recv_finished
          terminate(:decrypt_error) unless verify_finished
          send_ccs # compatibility mode
          @transcript[EOED] = send_eoed \
            if use_early_data? && accepted_early_data?
          # TODO: Send Certificate [+ CertificateVerify]
          @transcript[CF] = send_finished
          @write_cipher = gen_cipher(@cipher_suite,
                                     @key_schedule.client_application_write_key,
                                     @key_schedule.client_application_write_iv)
          @read_cipher = gen_cipher(@cipher_suite,
                                    @key_schedule.server_application_write_key,
                                    @key_schedule.server_application_write_iv)
          @state = ClientState::CONNECTED
        when ClientState::CONNECTED
          logger.debug('ClientState::WAIT_EE')

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
    def accepted_early_data?
      @accepted_early_data
    end

    private

    DOWNGRADE_PROTECTION_TLS_1_2 = "\x44\x4F\x57\x4E\x47\x52\x44\x01"
    DOWNGRADE_PROTECTION_TLS_1_1 = "\x44\x4F\x57\x4E\x47\x52\x44\x00"

    # @return [Boolean]
    # rubocop: disable Metrics/AbcSize
    # rubocop: disable Metrics/CyclomaticComplexity
    # rubocop: disable Metrics/PerceivedComplexity
    def valid_settings?
      cs = CipherSuite
      defined_cipher_suites = cs.constants.map { |c| cs.const_get(c) }
      return false \
        unless (@settings[:cipher_suites] - defined_cipher_suites).empty?

      sa = @settings[:signature_algorithms]
      ss = SignatureScheme
      defined_signature_schemes = ss.constants.map { |c| ss.const_get(c) }
      return false \
        unless (sa - defined_signature_schemes).empty?

      sac = @settings[:signature_algorithms_cert] || []
      return false \
        unless (sac - defined_signature_schemes).empty?

      sg = @settings[:supported_groups]
      ng = Message::Extension::NamedGroup
      defined_named_groups = ng.constants.map { |c| ng.const_get(c) }
      return false \
        unless (sg - defined_named_groups).empty?

      ksg = @settings[:key_share_groups]
      return false unless ksg.nil? || ((ksg - sg).empty? &&
                                       sg.select { |g| ksg.include?(g) } == ksg)

      true
    end
    # rubocop: enable Metrics/AbcSize
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

    def send_early_data
      ap = Message::ApplicationData.new(@early_data)
      ap_record = Message::Record.new(
        type: Message::ContentType::APPLICATION_DATA,
        legacy_record_version: Message::ProtocolVersion::TLS_1_2,
        messages: [ap],
        cipher: @early_data_write_cipher
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
      @priv_keys = priv_keys.merge(@priv_keys)

      # server_name
      exs << Message::Extension::ServerName.new(@hostname) \
        if !@hostname.nil? && !@hostname.empty?

      # early_data
      exs << Message::Extension::EarlyDataIndication.new if use_early_data?

      Message::Extensions.new(exs)
    end
    # rubocop: enable Metrics/AbcSize
    # rubocop: enable Metrics/CyclomaticComplexity

    # @return [TTTLS13::Message::ClientHello]
    def send_client_hello
      ch = Message::ClientHello.new(
        cipher_suites: CipherSuites.new(@settings[:cipher_suites]),
        extensions: gen_ch_extensions
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
        sign_psk_binder(ch)
      end

      send_handshakes(Message::ContentType::HANDSHAKE, [ch], @write_cipher)

      ch
    end

    # @param ch [TTTLS13::Message::ClientHello]
    #
    # @return [String]
    def sign_psk_binder(ch)
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
      @transcript[CH] = ch

      # TODO: ext binder
      psk.offered_psks.binders[0] = do_sign_psk_binder(digest)
    end

    # @return [Integer]
    def calc_obfuscated_ticket_age
      # the "ticket_lifetime" field in the NewSessionTicket message is
      # in seconds but the "obfuscated_ticket_age" is in milliseconds.
      age = (Time.now.to_f * 1000).to_i - @settings[:ticket_timestamp] * 1000
      (age + Convert.bin2i(@settings[:ticket_age_add])) % (2**32)
    end

    # NOTE:
    # https://tools.ietf.org/html/rfc8446#section-4.1.2
    #
    # @param ch1 [TTTLS13::Message::ClientHello]
    # @param hrr [TTTLS13::Message::ServerHello]
    #
    # @return [TTTLS13::Message::ClientHello]
    def send_new_client_hello(ch1, hrr)
      arr = []

      # key_share
      if hrr.extensions.include?(Message::ExtensionType::KEY_SHARE)
        group = hrr.extensions[Message::ExtensionType::KEY_SHARE]
                   .key_share_entry.first.group
        key_share, priv_keys \
                   = Message::Extension::KeyShare.gen_ch_key_share([group])
        arr << key_share
        @priv_keys = priv_keys.merge(@priv_keys)
      end

      # cookie
      #
      # When sending a HelloRetryRequest, the server MAY provide a "cookie"
      # extension to the client. When sending the new ClientHello, the client
      # MUST copy the contents of the extension received in the
      # HelloRetryRequest into a "cookie" extension in the new ClientHello.
      #
      # https://tools.ietf.org/html/rfc8446#section-4.2.2
      arr << hrr.extensions[Message::ExtensionType::COOKIE] \
        if hrr.extensions.include?(Message::ExtensionType::COOKIE)

      # early_data
      new_exs = ch1.extensions.merge(Message::Extensions.new(arr))
      new_exs.delete(Message::ExtensionType::EARLY_DATA)
      ch = Message::ClientHello.new(
        legacy_version: ch1.legacy_version,
        random: ch1.random,
        legacy_session_id: ch1.legacy_session_id,
        cipher_suites: ch1.cipher_suites,
        legacy_compression_methods: ch1.legacy_compression_methods,
        extensions: new_exs
      )
      send_handshakes(Message::ContentType::HANDSHAKE, [ch], @write_cipher)

      ch
    end

    # @raise [TTTLS13::Error::ErrorAlerts]
    #
    # @return [TTTLS13::Message::ServerHello]
    def recv_server_hello
      sh = recv_message
      terminate(:unexpected_message) unless sh.is_a?(Message::ServerHello)

      sh
    end

    # @raise [TTTLS13::Error::ErrorAlerts]
    #
    # @return [TTTLS13::Message::EncryptedExtensions]
    def recv_encrypted_extensions
      ee = recv_message
      terminate(:unexpected_message) \
        unless ee.is_a?(Message::EncryptedExtensions)

      ee
    end

    # @raise [TTTLS13::Error::ErrorAlerts]
    #
    # @return [TTTLS13::Message::Certificate]
    def recv_certificate
      ct = recv_message
      terminate(:unexpected_message) unless ct.is_a?(Message::Certificate)

      ct
    end

    # @raise [TTTLS13::Error::ErrorAlerts]
    #
    # @return [TTTLS13::Message::CertificateVerify]
    def recv_certificate_verify
      cv = recv_message
      terminate(:unexpected_message) unless cv.is_a?(Message::CertificateVerify)

      cv
    end

    # @raise [TTTLS13::Error::ErrorAlerts]
    #
    # @return [TTTLS13::Message::Finished]
    def recv_finished
      sf = recv_message
      terminate(:unexpected_message) unless sf.is_a?(Message::Finished)

      sf
    end

    # @return [TTTLS13::Message::Finished]
    def send_finished
      cf = Message::Finished.new(sign_finished)
      send_handshakes(Message::ContentType::APPLICATION_DATA, [cf],
                      @write_cipher)

      cf
    end

    # @return [TTTLS13::Message::EndOfEarlyData]
    def send_eoed
      eoed = Message::EndOfEarlyData.new
      send_handshakes(Message::ContentType::APPLICATION_DATA, [eoed],
                      @early_data_write_cipher)

      eoed
    end

    # @return [Boolean]
    def verify_certificate_verify
      ct = @transcript[CT]
      public_key = ct.certificate_list.first.cert_data.public_key
      cv = @transcript[CV]
      signature_scheme = cv.signature_scheme
      signature = cv.signature
      context = 'TLS 1.3, server CertificateVerify'
      do_verify_certificate_verify(public_key: public_key,
                                   signature_scheme: signature_scheme,
                                   signature: signature,
                                   context: context,
                                   handshake_context_end: CT)
    end

    # @return [String]
    def sign_finished
      digest = CipherSuite.digest(@cipher_suite)
      finished_key = @key_schedule.client_finished_key
      do_sign_finished(digest: digest,
                       finished_key: finished_key,
                       handshake_context_end: EOED)
    end

    # @return [Boolean]
    def verify_finished
      digest = CipherSuite.digest(@cipher_suite)
      finished_key = @key_schedule.server_finished_key
      signature = @transcript[SF].verify_data
      do_verify_finished(digest: digest,
                         finished_key: finished_key,
                         handshake_context_end: CV,
                         signature: signature)
    end

    # NOTE:
    # This implementation supports only TLS 1.3,
    # so negotiated_tls_1_3? assumes that it sent ClientHello with:
    #     1. supported_versions == ["\x03\x04"]
    #     2. legacy_versions == ["\x03\x03"]
    #
    # @return [Boolean]
    def negotiated_tls_1_3?
      sh = @transcript[SH]
      sh_lv = sh.legacy_version
      sh_sv = sh.extensions[Message::ExtensionType::SUPPORTED_VERSIONS]
                &.versions || []

      sh_lv == Message::ProtocolVersion::TLS_1_2 &&
        sh_sv.first == Message::ProtocolVersion::TLS_1_3
    end

    # @return [Boolean]
    def valid_sh_random?
      sh_r8 = @transcript[SH].random[-8..]

      sh_r8 != DOWNGRADE_PROTECTION_TLS_1_2 &&
        sh_r8 != DOWNGRADE_PROTECTION_TLS_1_1
    end

    # @return [Boolean]
    def valid_sh_legacy_version?
      @transcript[CH].legacy_version ==
        @transcript[SH].legacy_version
    end

    # @return [Boolean]
    def valid_sh_legacy_session_id_echo?
      @transcript[CH].legacy_session_id ==
        @transcript[SH].legacy_session_id_echo
    end

    # @return [Boolean]
    def valid_sh_cipher_suite?
      @transcript[CH].cipher_suites.include?(@transcript[SH].cipher_suite)
    end

    # @return [Boolean]
    def valid_sh_compression_method?
      @transcript[SH].legacy_compression_method == "\x00"
    end

    # @param extensions [TTTLS13::Message::Extensions]
    # @param transcript_index [Integer]
    #
    # @return [Boolean]
    def offered_ch_extensions?(extensions, transcript_index = nil)
      keys = extensions.keys
      if transcript_index == HRR
        keys -= @transcript[CH1].extensions.keys
        keys -= [Message::ExtensionType::COOKIE]
      else
        keys -= @transcript[CH].extensions.keys
      end
      keys.empty?
    end

    # @return [Boolean]
    def received_2nd_hrr?
      @transcript.include?(HRR)
    end

    # @param cipher_suite [TTTLS13::CipherSuite]
    #
    # @return [Boolean]
    def neq_hrr_cipher_suite?(cipher_suite)
      cipher_suite != @transcript[HRR].cipher_suite
    end

    # @param versions [Array of TTTLS13::Message::ProtocolVersion]
    #
    # @return [Boolean]
    def neq_hrr_supported_versions?(versions)
      hrr = @transcript[HRR]
      versions != hrr.extensions[Message::ExtensionType::SUPPORTED_VERSIONS]
                     .versions
    end

    # @return [Boolean]
    def valid_sh_key_share?
      offered = @transcript[CH].extensions[Message::ExtensionType::KEY_SHARE]
                               .key_share_entry.map(&:group)
      selected = @transcript[CH].extensions[Message::ExtensionType::KEY_SHARE]
                                .key_share_entry.first.group
      offered.include?(selected)
    end

    # @return [Boolean]
    def valid_hrr_key_share?
      # TODO: pre_shared_key
      ch1_exs = @transcript[CH1].extensions
      ngl = ch1_exs[Message::ExtensionType::SUPPORTED_GROUPS].named_group_list
      group = @transcript[HRR].extensions[Message::ExtensionType::KEY_SHARE]
                              .key_share_entry.first.group
      return false unless ngl.include?(group)

      kse = ch1_exs[Message::ExtensionType::KEY_SHARE].key_share_entry
      return false if !kse.empty? && kse.map(&:group).include?(group)

      true
    end

    # @param nst [TTTLS13::Message::NewSessionTicket]
    #
    # @raise [TTTLS13::Error::ErrorAlerts]
    def process_new_session_ticket(nst)
      super(nst)

      rms = @key_schedule.resumption_master_secret
      cs = @cipher_suite
      @settings[:process_new_session_ticket]&.call(nst, rms, cs)
    end
  end
  # rubocop: enable Metrics/ClassLength
end
