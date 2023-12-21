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

  DEFALUT_CH_COMPRESS_CERTIFICATE_ALGORITHMS = [
    Message::Extension::CertificateCompressionAlgorithm::ZLIB
  ].freeze
  private_constant :DEFALUT_CH_COMPRESS_CERTIFICATE_ALGORITHMS

  DEFAULT_CLIENT_SETTINGS = {
    ca_file: nil,
    cipher_suites: DEFAULT_CH_CIPHER_SUITES,
    signature_algorithms: DEFAULT_CH_SIGNATURE_ALGORITHMS,
    signature_algorithms_cert: nil,
    supported_groups: DEFAULT_CH_NAMED_GROUP_LIST,
    key_share_groups: nil,
    alpn: nil,
    process_new_session_ticket: nil,
    ticket: nil,
    # @deprecated Please use `resumption_secret` instead
    resumption_master_secret: nil,
    resumption_secret: nil,
    psk_cipher_suite: nil,
    ticket_nonce: nil,
    ticket_age_add: nil,
    ticket_timestamp: nil,
    record_size_limit: nil,
    check_certificate_status: false,
    process_certificate_status: nil,
    compress_certificate_algorithms: DEFALUT_CH_COMPRESS_CERTIFICATE_ALGORITHMS,
    ech_config: nil,
    ech_hpke_cipher_suites: nil,
    compatibility_mode: true,
    sslkeylogfile: nil,
    loglevel: Logger::WARN
  }.freeze
  private_constant :DEFAULT_CLIENT_SETTINGS

  STANDARD_CLIENT_ECH_HPKE_SYMMETRIC_CIPHER_SUITES = [
    HpkeSymmetricCipherSuite.new(
      HpkeSymmetricCipherSuite::HpkeKdfId.new(
        Hpke::KdfId::HKDF_SHA256
      ),
      HpkeSymmetricCipherSuite::HpkeAeadId.new(
        Hpke::AeadId::AES_128_GCM
      )
    )
  ].freeze
  # rubocop: disable Metrics/ClassLength
  class Client < Connection
    HpkeSymmetricCipherSuit = \
      ECHConfig::ECHConfigContents::HpkeKeyConfig::HpkeSymmetricCipherSuite

    # @param socket [Socket]
    # @param hostname [String]
    # @param settings [Hash]
    def initialize(socket, hostname, **settings)
      super(socket)

      @endpoint = :client
      @hostname = hostname
      @settings = DEFAULT_CLIENT_SETTINGS.merge(settings)
      # NOTE: backward compatibility
      if @settings[:resumption_secret].nil? &&
         !@settings[:resumption_master_secret].nil?
        @settings[:resumption_secret] =
          @settings.delete(:resumption_master_secret) \
      end
      raise Error::ConfigError if @settings[:resumption_secret] !=
                                  @settings[:resumption_master_secret]

      logger.level = @settings[:loglevel]

      @early_data = ''
      @succeed_early_data = false
      @retry_configs = []
      @rejected_ech = false
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
    # https://datatracker.ietf.org/doc/html/rfc8446#appendix-A.1
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
          @settings[:resumption_secret],
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
      sslkeylogfile = nil # TTTLS13::SslKeyLogFile::Writer
      ch1_outer = nil # TTTLS13::Message::ClientHello for rejected ECH
      ch_outer = nil # TTTLS13::Message::ClientHello for rejected ECH
      ech_state = nil # TTTLS13::Client::EchState for ECH with HRR
      unless @settings[:sslkeylogfile].nil?
        begin
          sslkeylogfile = SslKeyLogFile::Writer.new(@settings[:sslkeylogfile])
        rescue SystemCallError => e
          msg = "\"#{@settings[:sslkeylogfile]}\" file can NOT open: #{e}"
          logger.warn(msg)
        end
      end

      @state = ClientState::START
      loop do
        case @state
        when ClientState::START
          logger.debug('ClientState::START')

          extensions, priv_keys = gen_ch_extensions
          binder_key = (use_psk? ? key_schedule.binder_key_res : nil)
          ch, inner, ech_state = send_client_hello(extensions, binder_key)
          ch_outer = ch
          # use ClientHelloInner messages for the transcript hash
          ch = inner.nil? ? ch : inner
          transcript[CH] = [ch, ch.serialize]
          send_ccs if @settings[:compatibility_mode]
          if use_early_data?
            e_wcipher = gen_cipher(
              @settings[:psk_cipher_suite],
              key_schedule.early_data_write_key,
              key_schedule.early_data_write_iv
            )
            sslkeylogfile&.write_client_early_traffic_secret(
              transcript[CH].first.random,
              key_schedule.client_early_traffic_secret
            )
            send_early_data(e_wcipher)
          end

          @state = ClientState::WAIT_SH
        when ClientState::WAIT_SH
          logger.debug('ClientState::WAIT_SH')

          sh, = transcript[SH] = recv_server_hello

          # downgrade protection
          if !sh.negotiated_tls_1_3? && sh.downgraded?
            terminate(:illegal_parameter)
          # support only TLS 1.3
          elsif !sh.negotiated_tls_1_3?
            terminate(:protocol_version)
          end

          # validate parameters
          terminate(:illegal_parameter) \
            unless sh.appearable_extensions?
          terminate(:illegal_parameter) \
            unless sh.legacy_compression_method == "\x00"

          # validate sh using ch
          ch, = transcript[CH]
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
            hrr, = transcript[HRR]
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

            ch1, = transcript[CH1] = transcript.delete(CH)
            hrr, = transcript[HRR] = transcript.delete(SH)
            ch1_outer = ch_outer
            ch_outer = nil

            # validate cookie
            diff_sets = sh.extensions.keys - ch1.extensions.keys
            terminate(:unsupported_extension) \
              unless (diff_sets - [Message::ExtensionType::COOKIE]).empty?

            # validate key_share
            # TODO: validate pre_shared_key
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
            binder_key = (use_psk? ? key_schedule.binder_key_res : nil)
            ch, inner = send_new_client_hello(
              ch1,
              hrr,
              extensions,
              binder_key,
              ech_state
            )
            # use ClientHelloInner messages for the transcript hash
            ch = inner.nil? ? ch : inner
            transcript[CH] = [ch, ch.serialize]

            @state = ClientState::WAIT_SH
            next
          end

          # generate shared secret
          if sh.extensions.include?(Message::ExtensionType::PRE_SHARED_KEY)
          # TODO: validate pre_shared_key
          else
            psk = nil
          end
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

          # rejected ECH
          # NOTE: It can compute (hrr_)accept_ech until client selects the
          # cipher_suite.
          if !sh.hrr? && use_ech?
            if !transcript.include?(HRR) && !key_schedule.accept_ech?
              # 1sh SH
              transcript[CH] = [ch_outer, ch_outer.serialize]
              @rejected_ech = true
            elsif transcript.include?(HRR) && !key_schedule.hrr_accept_ech?
              # 2nd SH
              transcript[CH1] = [ch1_outer, ch1_outer.serialize]
              transcript[CH] = [ch_outer, ch_outer.serialize]
              @rejected_ech = true
            end
          end

          @alert_wcipher = hs_wcipher = gen_cipher(
            @cipher_suite,
            key_schedule.client_handshake_write_key,
            key_schedule.client_handshake_write_iv
          )
          sslkeylogfile&.write_client_handshake_traffic_secret(
            transcript[CH].first.random,
            key_schedule.client_handshake_traffic_secret
          )
          hs_rcipher = gen_cipher(
            @cipher_suite,
            key_schedule.server_handshake_write_key,
            key_schedule.server_handshake_write_iv
          )
          sslkeylogfile&.write_server_handshake_traffic_secret(
            transcript[CH].first.random,
            key_schedule.server_handshake_traffic_secret
          )
          @state = ClientState::WAIT_EE
        when ClientState::WAIT_EE
          logger.debug('ClientState::WAIT_EE')

          ee, = transcript[EE] = recv_encrypted_extensions(hs_rcipher)
          terminate(:illegal_parameter) unless ee.appearable_extensions?

          ch, = transcript[CH]
          terminate(:unsupported_extension) \
            unless (ee.extensions.keys - ch.extensions.keys).empty?

          rsl = ee.extensions[Message::ExtensionType::RECORD_SIZE_LIMIT]
          @recv_record_size = rsl.record_size_limit unless rsl.nil?
          @succeed_early_data = true \
            if ee.extensions.include?(Message::ExtensionType::EARLY_DATA)
          @alpn = ee.extensions[
            Message::ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION
          ]&.protocol_name_list&.first
          @retry_configs = ee.extensions[
            Message::ExtensionType::ENCRYPTED_CLIENT_HELLO
          ]&.retry_configs
          terminate(:unsupported_extension) \
            if !rejected_ech? && !@retry_configs.nil?

          @state = ClientState::WAIT_CERT_CR
          @state = ClientState::WAIT_FINISHED unless psk.nil?
        when ClientState::WAIT_CERT_CR
          logger.debug('ClientState::WAIT_CERT_CR')

          message, orig_msg = recv_message(
            receivable_ccs: true,
            cipher: hs_rcipher
          )
          case message.msg_type
          when Message::HandshakeType::CERTIFICATE,
               Message::HandshakeType::COMPRESSED_CERTIFICATE
            ct, = transcript[CT] = [message, orig_msg]
            terminate(:bad_certificate) \
              if ct.is_a?(Message::CompressedCertificate) &&
                 !@settings[:compress_certificate_algorithms]
                 .include?(ct.algorithm)

            ct = ct.certificate_message \
              if ct.is_a?(Message::CompressedCertificate)
            alert = check_invalid_certificate(ct, transcript[CH].first)
            terminate(alert) unless alert.nil?

            @state = ClientState::WAIT_CV
          when Message::HandshakeType::CERTIFICATE_REQUEST
            transcript[CR] = [message, orig_msg]
            # TODO: client authentication
            @state = ClientState::WAIT_CERT
          else
            terminate(:unexpected_message)
          end
        when ClientState::WAIT_CERT
          logger.debug('ClientState::WAIT_CERT')

          ct, = transcript[CT] = recv_certificate(hs_rcipher)
          if ct.is_a?(Message::CompressedCertificate) &&
             !@settings[:compress_certificate_algorithms].include?(ct.algorithm)
            terminate(:bad_certificate)
          elsif ct.is_a?(Message::CompressedCertificate)
            ct = ct.certificate_message
          end

          alert = check_invalid_certificate(ct, transcript[CH].first)
          terminate(alert) unless alert.nil?

          @state = ClientState::WAIT_CV
        when ClientState::WAIT_CV
          logger.debug('ClientState::WAIT_CV')

          cv, = transcript[CV] = recv_certificate_verify(hs_rcipher)
          digest = CipherSuite.digest(@cipher_suite)
          hash = transcript.hash(digest, CT)
          ct, = transcript[CT]
          ct = ct.certificate_message \
            if ct.is_a?(Message::CompressedCertificate)
          terminate(:decrypt_error) \
            unless verified_certificate_verify?(ct, cv, hash)

          @signature_scheme = cv.signature_scheme
          @state = ClientState::WAIT_FINISHED
        when ClientState::WAIT_FINISHED
          logger.debug('ClientState::WAIT_FINISHED')

          sf, = transcript[SF] = recv_finished(hs_rcipher)
          digest = CipherSuite.digest(@cipher_suite)
          terminate(:decrypt_error) unless verified_finished?(
            finished: sf,
            digest: digest,
            finished_key: key_schedule.server_finished_key,
            hash: transcript.hash(digest, CV)
          )

          if use_early_data? && succeed_early_data?
            eoed = send_eoed(e_wcipher)
            transcript[EOED] = [eoed, eoed.serialize]
          end
          # TODO: Send Certificate [+ CertificateVerify]
          signature = sign_finished(
            digest: digest,
            finished_key: key_schedule.client_finished_key,
            hash: transcript.hash(digest, EOED)
          )
          cf = send_finished(signature, hs_wcipher)
          transcript[CF] = [cf, cf.serialize]
          @alert_wcipher = @ap_wcipher = gen_cipher(
            @cipher_suite,
            key_schedule.client_application_write_key,
            key_schedule.client_application_write_iv
          )
          sslkeylogfile&.write_client_traffic_secret_0(
            transcript[CH].first.random,
            key_schedule.client_application_traffic_secret
          )
          @ap_rcipher = gen_cipher(
            @cipher_suite,
            key_schedule.server_application_write_key,
            key_schedule.server_application_write_iv
          )
          sslkeylogfile&.write_server_traffic_secret_0(
            transcript[CH].first.random,
            key_schedule.server_application_traffic_secret
          )
          @exporter_secret = key_schedule.exporter_secret
          @resumption_secret = key_schedule.resumption_secret
          @state = ClientState::CONNECTED
        when ClientState::CONNECTED
          logger.debug('ClientState::CONNECTED')

          send_alert(:ech_required) \
            if use_ech? && (!@retry_configs.nil? && !@retry_configs.empty?)
          break
        end
      end
      sslkeylogfile&.close
    end
    # rubocop: enable Metrics/AbcSize
    # rubocop: enable Metrics/BlockLength
    # rubocop: enable Metrics/CyclomaticComplexity
    # rubocop: enable Metrics/MethodLength
    # rubocop: enable Metrics/PerceivedComplexity

    # @param binary [String]
    def write(binary)
      # the client can regard ECH as securely disabled by the server, and it
      # SHOULD retry the handshake with a new transport connection and ECH
      # disabled.
      if !@retry_configs.nil? && !@retry_configs.empty?
        msg = 'SHOULD retry the handshake with a new transport connection'
        logger.warn(msg)
        return
      end

      super(binary)
    end

    # @param binary [String]
    #
    # @raise [TTTLS13::Error::ConfigError]
    def early_data(binary)
      raise Error::ConfigError unless @state == INITIAL && use_psk?

      @early_data = binary
    end

    # @return [Array of ECHConfig]
    def retry_configs
      @retry_configs.filter do |c|
        SUPPORTED_ECHCONFIG_VERSIONS.include?(c.version)
      end
    end

    # @return [Boolean]
    def succeed_early_data?
      @succeed_early_data
    end

    # @return [Boolean]
    def rejected_ech?
      @rejected_ech
    end

    # @param res [OpenSSL::OCSP::Response]
    # @param cert [OpenSSL::X509::Certificate]
    # @param chain [Array of OpenSSL::X509::Certificate, nil]
    #
    # @return [Boolean]
    #
    # @example
    #   m = Client.method(:softfail_check_certificate_status)
    #   Client.new(
    #     socket,
    #     hostname,
    #     check_certificate_status: true,
    #     process_certificate_status: m
    #   )
    def self.softfail_check_certificate_status(res, cert, chain)
      ocsp_response = res
      cid = OpenSSL::OCSP::CertificateId.new(cert, chain.first)

      # When NOT received OCSPResponse in TLS handshake, this method will
      # send OCSPRequest. If ocsp_uri is NOT presented in Certificate, return
      # true. Also, if it sends OCSPRequest and does NOT receive a HTTPresponse
      # within 2 seconds, return true.
      if ocsp_response.nil?
        uri = cert.ocsp_uris&.find { |u| URI::DEFAULT_PARSER.make_regexp =~ u }
        return true if uri.nil?

        begin
          # send OCSP::Request
          ocsp_request = gen_ocsp_request(cid)
          Timeout.timeout(2) do
            ocsp_response = send_ocsp_request(ocsp_request, uri)
          end

          # check nonce of OCSP::Response
          check_nonce = ocsp_request.check_nonce(ocsp_response.basic)
          return true unless [-1, 1].include?(check_nonce)
        rescue StandardError
          return true
        end
      end
      return true \
        if ocsp_response.status != OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL

      status = ocsp_response.basic.status.find { |s| s.first.cmp(cid) }
      status[1] != OpenSSL::OCSP::V_CERTSTATUS_REVOKED
    end

    private

    # @return [Boolean]
    # rubocop: disable Metrics/AbcSize
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

      rsl = @settings[:record_size_limit]
      return false if !rsl.nil? && (rsl < 64 || rsl > 2**14 + 1)

      return false if @settings[:check_certificate_status] &&
                      @settings[:process_certificate_status].nil?

      ehcs = @settings[:ech_hpke_cipher_suites] || []
      return false if !@settings[:ech_config].nil? && ehcs.empty?

      true
    end
    # rubocop: enable Metrics/AbcSize
    # rubocop: enable Metrics/CyclomaticComplexity
    # rubocop: enable Metrics/PerceivedComplexity

    # @return [Boolean]
    def use_psk?
      !@settings[:ticket].nil? &&
        !@settings[:resumption_secret].nil? &&
        !@settings[:psk_cipher_suite].nil? &&
        !@settings[:ticket_nonce].nil? &&
        !@settings[:ticket_age_add].nil? &&
        !@settings[:ticket_timestamp].nil?
    end

    # @return [Boolean]
    def use_early_data?
      !(@early_data.nil? || @early_data.empty?)
    end

    # @return [Boolean]
    def use_ech?
      !@settings[:ech_hpke_cipher_suites].nil? &&
        !@settings[:ech_hpke_cipher_suites].empty?
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

    # @param resumption_secret [String]
    # @param ticket_nonce [String]
    # @param digest [String] name of digest algorithm
    #
    # @return [String]
    def gen_psk_from_nst(resumption_secret, ticket_nonce, digest)
      hash_len = OpenSSL::Digest.new(digest).digest_length
      KeySchedule.hkdf_expand_label(resumption_secret, 'resumption',
                                    ticket_nonce, hash_len, digest)
    end

    # @return [TTTLS13::Message::Extensions]
    # @return [Hash of NamedGroup => OpenSSL::PKey::EC.$Object]
    # rubocop: disable Metrics/AbcSize
    # rubocop: disable Metrics/CyclomaticComplexity
    # rubocop: disable Metrics/MethodLength
    # rubocop: disable Metrics/PerceivedComplexity
    def gen_ch_extensions
      exs = Message::Extensions.new
      # server_name
      exs << Message::Extension::ServerName.new(@hostname)

      # record_size_limit
      unless @settings[:record_size_limit].nil?
        exs << Message::Extension::RecordSizeLimit.new(
          @settings[:record_size_limit]
        )
      end

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

      # early_data
      exs << Message::Extension::EarlyDataIndication.new if use_early_data?

      # alpn
      exs << Message::Extension::Alpn.new(@settings[:alpn].reject(&:empty?)) \
        if !@settings[:alpn].nil? && !@settings[:alpn].empty?

      # status_request
      exs << Message::Extension::OCSPStatusRequest.new \
        if @settings[:check_certificate_status]

      # compress_certificate
      if !@settings[:compress_certificate_algorithms].nil? &&
         !@settings[:compress_certificate_algorithms].empty?
        exs << Message::Extension::CompressCertificate.new(
          @settings[:compress_certificate_algorithms]
        )
      end

      [exs, priv_keys]
    end
    # rubocop: enable Metrics/AbcSize
    # rubocop: enable Metrics/CyclomaticComplexity
    # rubocop: enable Metrics/MethodLength
    # rubocop: enable Metrics/PerceivedComplexity

    # @param extensions [TTTLS13::Message::Extensions]
    # @param binder_key [String, nil]
    #
    # @return [TTTLS13::Message::ClientHello] outer
    # @return [TTTLS13::Message::ClientHello] inner
    # @return [TTTLS13::Client::EchState]
    # rubocop: disable Metrics/MethodLength
    def send_client_hello(extensions, binder_key = nil)
      ch = Message::ClientHello.new(
        cipher_suites: CipherSuites.new(@settings[:cipher_suites]),
        extensions: extensions
      )

      # encrypted_client_hello
      inner = nil # TTTLS13::Message::ClientHello
      if use_ech?
        inner = ch
        inner_ech = Message::Extension::ECHClientHello.new_inner
        inner.extensions[Message::ExtensionType::ENCRYPTED_CLIENT_HELLO] \
          = inner_ech
        ch, inner, ech_state = offer_ech(inner, @settings[:ech_config])
      end

      # psk_key_exchange_modes
      # In order to use PSKs, clients MUST also send a
      # "psk_key_exchange_modes" extension.
      #
      # https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.9
      if use_psk?
        pkem = Message::Extension::PskKeyExchangeModes.new(
          [Message::Extension::PskKeyExchangeMode::PSK_DHE_KE]
        )
        ch.extensions[Message::ExtensionType::PSK_KEY_EXCHANGE_MODES] = pkem
      end

      # pre_shared_key
      # at the end, sign PSK binder
      if use_psk?
        sign_psk_binder(
          ch: ch,
          binder_key: binder_key
        )

        if use_ech?
          sign_grease_psk_binder(
            ch_outer: ch,
            inner_pks: inner.extensions[Message::ExtensionType::PRE_SHARED_KEY]
          )
        end
      end

      send_handshakes(Message::ContentType::HANDSHAKE, [ch],
                      Cryptograph::Passer.new)

      [ch, inner, ech_state]
    end
    # rubocop: enable Metrics/MethodLength

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
      # https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11.2
      digest = CipherSuite.digest(@settings[:psk_cipher_suite])
      hash_len = OpenSSL::Digest.new(digest).digest_length
      placeholder_binders = [hash_len.zeros]
      psk = Message::Extension::PreSharedKey.new(
        msg_type: Message::HandshakeType::CLIENT_HELLO,
        offered_psks: Message::Extension::OfferedPsks.new(
          identities: [Message::Extension::PskIdentity.new(
            identity: @settings[:ticket],
            obfuscated_ticket_age: calc_obfuscated_ticket_age
          )],
          binders: placeholder_binders
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

    # @param ch1 [TTTLS13::Message::ClientHello]
    # @param hrr [TTTLS13::Message::ServerHello]
    # @param ch_outer [TTTLS13::Message::ClientHello]
    # @param inner_psk [Message::Extension::PreSharedKey]
    # @param binder_key [String]
    #
    # @return [String]
    def sign_grease_psk_binder(ch1: nil,
                               hrr: nil,
                               ch_outer:,
                               inner_psk:,
                               binder_key:)
      digest = CipherSuite.digest(@settings[:psk_cipher_suite])
      hash_len = OpenSSL::Digest.new(digest).digest_length
      placeholder_binders = [hash_len.zeros]
      # For each PSK identity advertised in the ClientHelloInner, the client
      # generates a random PSK identity with the same length. It also generates
      # a random, 32-bit, unsigned integer to use as the obfuscated_ticket_age.
      # Likewise, for each inner PSK binder, the client generates a random
      # string of the same length.
      #
      # https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-17#section-6.1.2-2
      identity = inner_psk.offered_psks
                          .identities
                          .first
                          .identity
                          .length
                          .then { |len| OpenSSL::Random.random_bytes(len) }
      ota = OpenSSL::Random.random_bytes(4)
      psk = Message::Extension::PreSharedKey.new(
        msg_type: Message::HandshakeType::CLIENT_HELLO,
        offered_psks: Message::Extension::OfferedPsks.new(
          identities: [Message::Extension::PskIdentity.new(
            identity: identity,
            obfuscated_ticket_age: ota
          )],
          binders: placeholder_binders
        )
      )
      ch_outer.extensions[Message::ExtensionType::PRE_SHARED_KEY] = psk

      psk.offered_psks.binders[0] = do_sign_psk_binder(
        ch1: ch1,
        hrr: hrr,
        ch: ch_outer,
        binder_key: binder_key,
        digest: digest
      )
    end

    # @param inner [TTTLS13::Message::ClientHello]
    # @param ech_config [ECHConfig]
    #
    # @return [TTTLS13::Message::ClientHello]
    # @return [TTTLS13::Message::ClientHello]
    # @return [TTTLS13::Client::EchState]
    # rubocop: disable Metrics/AbcSize
    # rubocop: disable Metrics/MethodLength
    def offer_ech(inner, ech_config)
      return [new_greased_ch(inner, new_grease_ech), nil, nil] \
        if ech_config.nil? ||
           !SUPPORTED_ECHCONFIG_VERSIONS.include?(ech_config.version)

      # Encrypted ClientHello Configuration
      public_name = ech_config.echconfig_contents.public_name
      key_config = ech_config.echconfig_contents.key_config
      public_key = key_config.public_key.opaque
      kem_id = key_config&.kem_id&.uint16
      config_id = key_config.config_id
      cipher_suite = select_ech_hpke_cipher_suite(key_config)
      overhead_len = Hpke.aead_id2overhead_len(cipher_suite&.aead_id&.uint16)
      aead_cipher = Hpke.aead_id2aead_cipher(cipher_suite&.aead_id&.uint16)
      kdf_hash = Hpke.kdf_id2kdf_hash(cipher_suite&.kdf_id&.uint16)
      return [new_greased_ch(inner, new_grease_ech), nil, nil] \
        if [kem_id, overhead_len, aead_cipher, kdf_hash].any?(&:nil?)

      kem_curve_name, kem_hash = Hpke.kem_id2dhkem(kem_id)
      dhkem = Hpke.kem_curve_name2dhkem(kem_curve_name)
      pkr = dhkem&.new(kem_hash)&.deserialize_public_key(public_key)
      return [new_greased_ch(inner, new_grease_ech), nil, nil] if pkr.nil?

      hpke = HPKE.new(kem_curve_name, kem_hash, kdf_hash, aead_cipher)
      base_s = hpke.setup_base_s(pkr, "tls ech\x00" + ech_config.encode)
      enc = base_s[:enc]
      ctx = base_s[:context_s]
      mnl = ech_config.echconfig_contents.maximum_name_length
      encoded = encode_ch_inner(inner, mnl)

      # Encoding the ClientHelloInner
      aad = new_ch_outer_aad(
        inner,
        cipher_suite,
        config_id,
        enc,
        encoded.length + overhead_len,
        public_name
      )
      # Authenticating the ClientHelloOuter
      # which does not include the Handshake structure's four byte header.
      outer = new_ch_outer(
        aad,
        cipher_suite,
        config_id,
        enc,
        ctx.seal(aad.serialize[4..], encoded)
      )

      ech_state = EchState.new(mnl, config_id, cipher_suite, public_name, ctx)
      [outer, inner, ech_state]
    end
    # rubocop: enable Metrics/AbcSize
    # rubocop: enable Metrics/MethodLength

    # @param inner [TTTLS13::Message::ClientHello]
    # @param ech_state [TTTLS13::Client::EchState]
    #
    # @return [TTTLS13::Message::ClientHello]
    # @return [TTTLS13::Message::ClientHello]
    def offer_ech_hrr(inner, ech_state)
      encoded = encode_ch_inner(inner, ech_state.maximum_name_length)
      overhead_len \
        = Hpke.aead_id2overhead_len(ech_state.cipher_suite.aead_id.uint16)

      # It encrypts EncodedClientHelloInner as described in Section 6.1.1, using
      # the second partial ClientHelloOuterAAD, to obtain a second
      # ClientHelloOuter. It reuses the original HPKE encryption context
      # computed in Section 6.1 and uses the empty string for enc.
      #
      # https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-17#section-6.1.5-4.4.1
      aad = new_ch_outer_aad(
        inner,
        ech_state.cipher_suite,
        ech_state.config_id,
        '',
        encoded.length + overhead_len,
        ech_state.public_name
      )
      # Authenticating the ClientHelloOuter
      # which does not include the Handshake structure's four byte header.
      outer = new_ch_outer(
        aad,
        ech_state.cipher_suite,
        ech_state.config_id,
        '',
        ech_state.ctx.seal(aad.serialize[4..], encoded)
      )

      [outer, inner]
    end

    # @param inner [TTTLS13::Message::ClientHello]
    # @param maximum_name_length [Integer]
    #
    # @return [String] EncodedClientHelloInner
    def encode_ch_inner(inner, maximum_name_length)
      # TODO: ech_outer_extensions
      encoded = Message::ClientHello.new(
        legacy_version: inner.legacy_version,
        random: inner.random,
        legacy_session_id: '',
        cipher_suites: inner.cipher_suites,
        legacy_compression_methods: inner.legacy_compression_methods,
        extensions: inner.extensions
      )
      server_name_length = \
        inner.extensions[Message::ExtensionType::SERVER_NAME].server_name.length

      # which does not include the Handshake structure's four byte header.
      padding_encoded_ch_inner(
        encoded.serialize[4..],
        server_name_length,
        maximum_name_length
      )
    end

    # @param s [String]
    # @param server_name_length [Integer]
    # @param maximum_name_length [Integer]
    #
    # @return [String]
    def padding_encoded_ch_inner(s, server_name_length, maximum_name_length)
      padding_len =
        if server_name_length.positive?
          [maximum_name_length - server_name_length, 0].max
        else
          9 + maximum_name_length
        end

      padding_len = 31 - ((s.length + padding_len - 1) % 32)
      s + padding_len.zeros
    end

    # @param inner [TTTLS13::Message::ClientHello]
    # @param cipher_suite [HpkeSymmetricCipherSuite]
    # @param config_id [Integer]
    # @param enc [String]
    # @param payload_len [Integer]
    # @param server_name [String]
    #
    # @return [TTTLS13::Message::ClientHello]
    # rubocop: disable Metrics/ParameterLists
    def new_ch_outer_aad(inner,
                         cipher_suite,
                         config_id,
                         enc,
                         payload_len,
                         server_name)
      aad_ech = Message::Extension::ECHClientHello.new_outer(
        cipher_suite: cipher_suite,
        config_id: config_id,
        enc: enc,
        payload: payload_len.zeros
      )
      Message::ClientHello.new(
        legacy_version: inner.legacy_version,
        legacy_session_id: inner.legacy_session_id,
        cipher_suites: inner.cipher_suites,
        legacy_compression_methods: inner.legacy_compression_methods,
        extensions: inner.extensions.merge(
          Message::ExtensionType::ENCRYPTED_CLIENT_HELLO => aad_ech,
          Message::ExtensionType::SERVER_NAME => \
            Message::Extension::ServerName.new(server_name)
        )
      )
    end
    # rubocop: enable Metrics/ParameterLists

    # @param inner [TTTLS13::Message::ClientHello]
    # @param cipher_suite [HpkeSymmetricCipherSuite]
    # @param config_id [Integer]
    # @param enc [String]
    # @param payload [String]
    #
    # @return [TTTLS13::Message::ClientHello]
    def new_ch_outer(aad, cipher_suite, config_id, enc, payload)
      outer_ech = Message::Extension::ECHClientHello.new_outer(
        cipher_suite: cipher_suite,
        config_id: config_id,
        enc: enc,
        payload: payload
      )
      Message::ClientHello.new(
        legacy_version: aad.legacy_version,
        random: aad.random,
        legacy_session_id: aad.legacy_session_id,
        cipher_suites: aad.cipher_suites,
        legacy_compression_methods: aad.legacy_compression_methods,
        extensions: aad.extensions.merge(
          Message::ExtensionType::ENCRYPTED_CLIENT_HELLO => outer_ech
        )
      )
    end

    # @param conf [HpkeKeyConfig]
    #
    # @return [HpkeSymmetricCipherSuite, nil]
    def select_ech_hpke_cipher_suite(conf)
      @settings[:ech_hpke_cipher_suites].find do |cs|
        conf.cipher_suites.include?(cs)
      end
    end

    # @return [Message::Extension::ECHClientHello]
    def new_grease_ech
      # https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-17#name-compliance-requirements
      cipher_suite = HpkeSymmetricCipherSuite.new(
        HpkeSymmetricCipherSuite::HpkeKdfId.new(
          TTTLS13::Hpke::KdfId::HKDF_SHA256
        ),
        HpkeSymmetricCipherSuite::HpkeAeadId.new(
          TTTLS13::Hpke::AeadId::AES_128_GCM
        )
      )
      # Set the enc field to a randomly-generated valid encapsulated public key
      # output by the HPKE KEM.
      #
      # https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-17#section-6.2-2.3.1
      public_key = OpenSSL::PKey.read(
        OpenSSL::PKey.generate_key('X25519').public_to_pem
      )
      hpke = HPKE.new(:x25519, :sha256, :sha256, :aes_128_gcm)
      enc = hpke.setup_base_s(public_key, '')[:enc]
      # Set the payload field to a randomly-generated string of L+C bytes, where
      # C is the ciphertext expansion of the selected AEAD scheme and L is the
      # size of the EncodedClientHelloInner the client would compute when
      # offering ECH, padded according to Section 6.1.3.
      #
      # https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-17#section-6.2-2.4.1
      payload_len = placeholder_encoded_ch_inner_len \
                    + Hpke.aead_id2overhead_len(Hpke::AeadId::AES_128_GCM)

      Message::Extension::ECHClientHello.new_outer(
        cipher_suite: cipher_suite,
        config_id: Convert.bin2i(OpenSSL::Random.random_bytes(1)),
        enc: enc,
        payload: OpenSSL::Random.random_bytes(payload_len)
      )
    end

    # @return [Integer]
    def placeholder_encoded_ch_inner_len
      448
    end

    # @param inner [TTTLS13::Message::ClientHello]
    # @param ech [Message::Extension::ECHClientHello]
    def new_greased_ch(inner, ech)
      Message::ClientHello.new(
        legacy_version: inner.legacy_version,
        random: inner.random,
        legacy_session_id: inner.legacy_session_id,
        cipher_suites: inner.cipher_suites,
        legacy_compression_methods: inner.legacy_compression_methods,
        extensions: inner.extensions.merge(
          Message::ExtensionType::ENCRYPTED_CLIENT_HELLO => ech
        )
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
      exs = Message::Extensions.new
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
      # https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.2
      exs << hrr.extensions[Message::ExtensionType::COOKIE] \
        if hrr.extensions.include?(Message::ExtensionType::COOKIE)

      # early_data
      new_exs = ch1.extensions.merge(exs)
      new_exs.delete(Message::ExtensionType::EARLY_DATA)

      [new_exs, priv_keys]
    end

    # NOTE:
    # https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
    #
    # @param ch1 [TTTLS13::Message::ClientHello]
    # @param hrr [TTTLS13::Message::ServerHello]
    # @param extensions [TTTLS13::Message::Extensions]
    # @param binder_key [String, nil]
    # @param ech_state [TTTLS13::Client::EchState]
    #
    # @return [TTTLS13::Message::ClientHello] outer
    # @return [TTTLS13::Message::ClientHello] inner
    def send_new_client_hello(ch1,
                              hrr,
                              extensions,
                              binder_key = nil,
                              ech_state = nil)
      ch = Message::ClientHello.new(
        legacy_version: ch1.legacy_version,
        random: ch1.random,
        legacy_session_id: ch1.legacy_session_id,
        cipher_suites: ch1.cipher_suites,
        legacy_compression_methods: ch1.legacy_compression_methods,
        extensions: extensions
      )

      # encrypted_client_hello
      ch, inner = offer_ech_hrr(ch, ech_state) if use_ech?

      # pre_shared_key
      #
      # Updating the "pre_shared_key" extension if present by recomputing
      # the "obfuscated_ticket_age" and binder values.
      if ch1.extensions.include?(Message::ExtensionType::PRE_SHARED_KEY)
        sign_psk_binder(ch1: ch1, hrr: hrr, ch: ch, binder_key: binder_key)

        if use_ech?
          sign_grease_psk_binder(
            ch1: ch1,
            hrr: hrr,
            ch_outer: ch,
            inner_psk: inner.extensions[Message::ExtensionType::PRE_SHARED_KEY],
            binder_key: binder_key
          )
        end
      end

      send_handshakes(Message::ContentType::HANDSHAKE, [ch],
                      Cryptograph::Passer.new)

      [ch, inner]
    end

    # @raise [TTTLS13::Error::ErrorAlerts]
    #
    # @return [TTTLS13::Message::ServerHello]
    # @return [String]
    def recv_server_hello
      sh, orig_msg = recv_message(
        receivable_ccs: true,
        cipher: Cryptograph::Passer.new
      )
      terminate(:unexpected_message) unless sh.is_a?(Message::ServerHello)

      [sh, orig_msg]
    end

    # @param cipher [TTTLS13::Cryptograph::Aead]
    #
    # @raise [TTTLS13::Error::ErrorAlerts]
    #
    # @return [TTTLS13::Message::EncryptedExtensions]
    # @return [String]
    def recv_encrypted_extensions(cipher)
      ee, orig_msg = recv_message(receivable_ccs: true, cipher: cipher)
      terminate(:unexpected_message) \
        unless ee.is_a?(Message::EncryptedExtensions)

      [ee, orig_msg]
    end

    # @param cipher [TTTLS13::Cryptograph::Aead]
    #
    # @raise [TTTLS13::Error::ErrorAlerts]
    #
    # @return [TTTLS13::Message::Certificate]
    # @return [String]
    def recv_certificate(cipher)
      ct, orig_msg = recv_message(receivable_ccs: true, cipher: cipher)
      terminate(:unexpected_message) unless ct.is_a?(Message::Certificate)

      [ct, orig_msg]
    end

    # @param cipher [TTTLS13::Cryptograph::Aead]
    #
    # @raise [TTTLS13::Error::ErrorAlerts]
    #
    # @return [TTTLS13::Message::CertificateVerify]
    # @return [String]
    def recv_certificate_verify(cipher)
      cv, orig_msg = recv_message(receivable_ccs: true, cipher: cipher)
      terminate(:unexpected_message) unless cv.is_a?(Message::CertificateVerify)

      [cv, orig_msg]
    end

    # @param cipher [TTTLS13::Cryptograph::Aead]
    #
    # @raise [TTTLS13::Error::ErrorAlerts]
    #
    # @return [TTTLS13::Message::Finished]
    # @return [String]
    def recv_finished(cipher)
      sf, orig_msg = recv_message(receivable_ccs: true, cipher: cipher)
      terminate(:unexpected_message) unless sf.is_a?(Message::Finished)

      [sf, orig_msg]
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
    # @param ch [TTTLS13::Message::ClientHello]
    #
    # @return [Symbol, nil] return key of ALERT_DESCRIPTION, if invalid
    def check_invalid_certificate(ct, ch)
      return :illegal_parameter unless ct.appearable_extensions?

      return :unsupported_extension \
        unless ct.certificate_list.map(&:extensions)
                 .all? { |e| (e.keys - ch.extensions.keys).empty? }

      return :certificate_unknown unless trusted_certificate?(
        ct.certificate_list,
        @settings[:ca_file],
        @hostname
      )

      if @settings[:check_certificate_status]
        ee = ct.certificate_list.first
        ocsp_response = ee.extensions[Message::ExtensionType::STATUS_REQUEST]
                         &.ocsp_response
        cert = ee.cert_data
        chain = ct.certificate_list[1..]&.map(&:cert_data)
        return :bad_certificate_status_response \
          unless satisfactory_certificate_status?(ocsp_response, cert, chain)
      end

      nil
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

    # @param ocsp_response [OpenSSL::OCSP::Response]
    # @param cert [OpenSSL::X509::Certificate]
    # @param chain [Array of OpenSSL::X509::Certificate, nil]
    #
    # @return [Boolean]
    def satisfactory_certificate_status?(ocsp_response, cert, chain)
      @settings[:process_certificate_status]&.call(ocsp_response, cert, chain)
    end

    # @param nst [TTTLS13::Message::NewSessionTicket]
    #
    # @raise [TTTLS13::Error::ErrorAlerts]
    def process_new_session_ticket(nst)
      super(nst)

      rms = @resumption_secret
      cs = @cipher_suite
      @settings[:process_new_session_ticket]&.call(nst, rms, cs)
    end

    class EchState
      attr_accessor :maximum_name_length
      attr_accessor :config_id
      attr_accessor :cipher_suite
      attr_accessor :public_name
      attr_accessor :ctx

      # @param maximum_name_length [Integer]
      # @param config_id [Integer]
      # @param cipher_suite [HpkeSymmetricCipherSuite]
      # @param public_name [String]
      # @param ctx [[HPKE::ContextS]
      def initialize(maximum_name_length,
                     config_id,
                     cipher_suite,
                     public_name,
                     ctx)
        @maximum_name_length = maximum_name_length
        @config_id = config_id
        @cipher_suite = cipher_suite
        @public_name = public_name
        @ctx = ctx
      end
    end
  end
  # rubocop: enable Metrics/ClassLength
end
