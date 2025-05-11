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
    NamedGroup::X25519,
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
        Ech::KdfId::HKDF_SHA256
      ),
      HpkeSymmetricCipherSuite::HpkeAeadId.new(
        Ech::AeadId::AES_128_GCM
      )
    )
  ].freeze
  # rubocop: disable Metrics/ClassLength
  class Client
    include Logging

    HpkeSymmetricCipherSuit \
      = ECHConfig::ECHConfigContents::HpkeKeyConfig::HpkeSymmetricCipherSuite

    attr_reader :transcript

    # @param socket [Socket]
    # @param hostname [String]
    # @param settings [Hash]
    def initialize(socket, hostname, **settings)
      @connection = Connection.new(socket, :client)
      @hostname = hostname
      @settings = DEFAULT_CLIENT_SETTINGS.merge(settings)
      logger.level = @settings[:loglevel]

      @early_data = ''
      @succeed_early_data = false
      @retry_configs = []
      @rejected_ech = false
      raise Error::ConfigError unless valid_settings?
    end

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
      @transcript = Transcript.new
      key_schedule = nil # TTTLS13::KeySchedule
      psk = nil
      if use_psk?
        psk = gen_psk_from_nst(
          @settings[:resumption_secret],
          @settings[:ticket_nonce],
          CipherSuite.digest(@settings[:psk_cipher_suite])
        )
        key_schedule = KeySchedule.new(
          psk:,
          shared_secret: nil,
          cipher_suite: @settings[:psk_cipher_suite],
          transcript: @transcript
        )
      end

      shared_secret = nil # TTTLS13::SharedSecret
      hs_wcipher = nil # TTTLS13::Cryptograph::$Object
      hs_rcipher = nil # TTTLS13::Cryptograph::$Object
      e_wcipher = nil # TTTLS13::Cryptograph::$Object
      sslkeylogfile = nil # TTTLS13::SslKeyLogFile::Writer
      ch1_outer = nil # TTTLS13::Message::ClientHello for rejected ECH
      ch_outer = nil # TTTLS13::Message::ClientHello for rejected ECH
      ech_state = nil # TTTLS13::EchState for ECH with HRR
      unless @settings[:sslkeylogfile].nil?
        begin
          sslkeylogfile = SslKeyLogFile::Writer.new(@settings[:sslkeylogfile])
        rescue SystemCallError => e
          msg = "\"#{@settings[:sslkeylogfile]}\" file can NOT open: #{e}"
          logger.warn(msg)
        end
      end

      @connection.state = ClientState::START
      loop do
        case @connection.state
        when ClientState::START
          logger.debug('ClientState::START')

          extensions, shared_secret = gen_ch_extensions
          binder_key = (use_psk? ? key_schedule.binder_key_res : nil)
          ch, inner, ech_state = send_client_hello(extensions, binder_key)
          ch_outer = ch
          # use ClientHelloInner messages for the transcript hash
          ch = inner.nil? ? ch : inner
          @transcript[CH] = [ch, ch.serialize]
          @connection.send_ccs if @settings[:compatibility_mode]
          if use_early_data?
            e_wcipher = Endpoint.gen_cipher(
              @settings[:psk_cipher_suite],
              key_schedule.early_data_write_key,
              key_schedule.early_data_write_iv
            )
            sslkeylogfile&.write_client_early_traffic_secret(
              @transcript[CH].first.random,
              key_schedule.client_early_traffic_secret
            )
            send_early_data(e_wcipher)
          end

          @connection.state = ClientState::WAIT_SH
        when ClientState::WAIT_SH
          logger.debug('ClientState::WAIT_SH')

          sh, = @transcript[SH] = recv_server_hello

          # downgrade protection
          if !sh.negotiated_tls_1_3? && sh.downgraded?
            @connection.terminate(:illegal_parameter)
          # support only TLS 1.3
          elsif !sh.negotiated_tls_1_3?
            @connection.terminate(:protocol_version)
          end

          # validate parameters
          @connection.terminate(:illegal_parameter) \
            unless sh.appearable_extensions?
          @connection.terminate(:illegal_parameter) \
            unless sh.legacy_compression_method == "\x00"

          # validate sh using ch
          ch, = @transcript[CH]
          @connection.terminate(:illegal_parameter) \
            unless sh.legacy_version == ch.legacy_version
          @connection.terminate(:illegal_parameter) \
            unless sh.legacy_session_id_echo == ch.legacy_session_id
          @connection.terminate(:illegal_parameter) \
            unless ch.cipher_suites.include?(sh.cipher_suite)
          @connection.terminate(:unsupported_extension) \
            unless (sh.extensions.keys - ch.extensions.keys).empty?

          # validate sh using hrr
          if @transcript.include?(HRR)
            hrr, = @transcript[HRR]
            @connection.terminate(:illegal_parameter) \
              unless sh.cipher_suite == hrr.cipher_suite

            sh_sv = sh.extensions[Message::ExtensionType::SUPPORTED_VERSIONS]
            hrr_sv = hrr.extensions[Message::ExtensionType::SUPPORTED_VERSIONS]
            @connection.terminate(:illegal_parameter) \
              unless sh_sv.versions == hrr_sv.versions
          end

          # handling HRR
          if sh.hrr?
            @connection.terminate(:unexpected_message) \
              if @transcript.include?(HRR)

            ch1, = @transcript[CH1] = @transcript.delete(CH)
            hrr, = @transcript[HRR] = @transcript.delete(SH)
            ch1_outer = ch_outer
            ch_outer = nil

            # validate cookie
            diff_sets = sh.extensions.keys - ch1.extensions.keys
            @connection.terminate(:unsupported_extension) \
              unless (diff_sets - [Message::ExtensionType::COOKIE]).empty?

            # validate key_share
            # TODO: validate pre_shared_key
            ngl = ch1.extensions[Message::ExtensionType::SUPPORTED_GROUPS]
                     .named_group_list
            kse = ch1.extensions[Message::ExtensionType::KEY_SHARE]
                     .key_share_entry
            group = hrr.extensions[Message::ExtensionType::KEY_SHARE]
                       .key_share_entry.first.group
            @connection.terminate(:illegal_parameter) \
              unless ngl.include?(group) && !kse.map(&:group).include?(group)

            # send new client_hello
            extensions, shared_secret = gen_newch_extensions(ch1, hrr)
            binder_key = (use_psk? ? key_schedule.binder_key_res : nil)
            ch, inner = send_new_client_hello(
              ch1,
              hrr,
              extensions,
              binder_key,
              ech_state
            )
            # use ClientHelloInner messages for the transcript hash
            ch_outer = ch
            ch = inner.nil? ? ch : inner
            @transcript[CH] = [ch, ch.serialize]

            @connection.state = ClientState::WAIT_SH
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
          @connection.terminate(:illegal_parameter) unless ch_ks.include?(sh_ks)

          kse = sh.extensions[Message::ExtensionType::KEY_SHARE]
                  .key_share_entry
                  .first
          ke = kse.key_exchange
          @named_group = kse.group
          @cipher_suite = sh.cipher_suite
          key_schedule = KeySchedule.new(
            psk:,
            shared_secret: shared_secret.build(@named_group, ke),
            cipher_suite: @cipher_suite,
            transcript: @transcript
          )

          # rejected ECH
          # It can compute (hrr_)accept_ech until client selects the
          # cipher_suite.
          if !sh.hrr? && use_ech?
            if !@transcript.include?(HRR) && !key_schedule.accept_ech?
              # 1sh SH
              @transcript[CH] = [ch_outer, ch_outer.serialize]
              @rejected_ech = true
            elsif @transcript.include?(HRR) &&
                  key_schedule.hrr_accept_ech? != key_schedule.accept_ech?
              # 2nd SH
              @connection.terminate(:illegal_parameter)
            elsif @transcript.include?(HRR) && !key_schedule.hrr_accept_ech?
              # 2nd SH
              @transcript[CH1] = [ch1_outer, ch1_outer.serialize]
              @transcript[CH] = [ch_outer, ch_outer.serialize]
              @rejected_ech = true
            end
          end

          @connection.alert_wcipher = hs_wcipher = Endpoint.gen_cipher(
            @cipher_suite,
            key_schedule.client_handshake_write_key,
            key_schedule.client_handshake_write_iv
          )
          sslkeylogfile&.write_client_handshake_traffic_secret(
            @transcript[CH].first.random,
            key_schedule.client_handshake_traffic_secret
          )
          hs_rcipher = Endpoint.gen_cipher(
            @cipher_suite,
            key_schedule.server_handshake_write_key,
            key_schedule.server_handshake_write_iv
          )
          sslkeylogfile&.write_server_handshake_traffic_secret(
            @transcript[CH].first.random,
            key_schedule.server_handshake_traffic_secret
          )
          @connection.state = ClientState::WAIT_EE
        when ClientState::WAIT_EE
          logger.debug('ClientState::WAIT_EE')

          ee, = @transcript[EE] = recv_encrypted_extensions(hs_rcipher)
          @connection.terminate(:illegal_parameter) \
            unless ee.appearable_extensions?

          ch, = @transcript[CH]
          @connection.terminate(:unsupported_extension) \
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
          @connection.terminate(:unsupported_extension) \
            if !rejected_ech? && !@retry_configs.nil?

          @connection.state = ClientState::WAIT_CERT_CR
          @connection.state = ClientState::WAIT_FINISHED unless psk.nil?
        when ClientState::WAIT_CERT_CR
          logger.debug('ClientState::WAIT_CERT_CR')

          message, orig_msg = @connection.recv_message(
            receivable_ccs: true,
            cipher: hs_rcipher
          )
          case message.msg_type
          when Message::HandshakeType::CERTIFICATE,
               Message::HandshakeType::COMPRESSED_CERTIFICATE
            ct, = @transcript[CT] = [message, orig_msg]
            @connection.terminate(:bad_certificate) \
              if ct.is_a?(Message::CompressedCertificate) &&
                 !@settings[:compress_certificate_algorithms]
                 .include?(ct.algorithm)

            ct = ct.certificate_message \
              if ct.is_a?(Message::CompressedCertificate)
            alert = check_invalid_certificate(ct, @transcript[CH].first)
            @connection.terminate(alert) unless alert.nil?

            @connection.state = ClientState::WAIT_CV
          when Message::HandshakeType::CERTIFICATE_REQUEST
            @transcript[CR] = [message, orig_msg]
            # TODO: client authentication
            @connection.state = ClientState::WAIT_CERT
          else
            @connection.terminate(:unexpected_message)
          end
        when ClientState::WAIT_CERT
          logger.debug('ClientState::WAIT_CERT')

          ct, = @transcript[CT] = recv_certificate(hs_rcipher)
          if ct.is_a?(Message::CompressedCertificate) &&
             !@settings[:compress_certificate_algorithms].include?(ct.algorithm)
            @connection.terminate(:bad_certificate)
          elsif ct.is_a?(Message::CompressedCertificate)
            ct = ct.certificate_message
          end

          alert = check_invalid_certificate(ct, @transcript[CH].first)
          @connection.terminate(alert) unless alert.nil?

          @connection.state = ClientState::WAIT_CV
        when ClientState::WAIT_CV
          logger.debug('ClientState::WAIT_CV')

          cv, = @transcript[CV] = recv_certificate_verify(hs_rcipher)
          digest = CipherSuite.digest(@cipher_suite)
          hash = @transcript.hash(digest, CT)
          ct, = @transcript[CT]
          ct = ct.certificate_message \
            if ct.is_a?(Message::CompressedCertificate)
          @connection.terminate(:decrypt_error) \
            unless verified_certificate_verify?(ct, cv, hash)

          @signature_scheme = cv.signature_scheme
          @connection.state = ClientState::WAIT_FINISHED
        when ClientState::WAIT_FINISHED
          logger.debug('ClientState::WAIT_FINISHED')

          sf, = @transcript[SF] = recv_finished(hs_rcipher)
          digest = CipherSuite.digest(@cipher_suite)
          @connection.terminate(:decrypt_error) \
            unless Endpoint.verified_finished?(
              finished: sf,
              digest:,
              finished_key: key_schedule.server_finished_key,
              hash: @transcript.hash(digest, CV)
            )

          if use_early_data? && succeed_early_data?
            eoed = send_eoed(e_wcipher)
            @transcript[EOED] = [eoed, eoed.serialize]
          end
          # TODO: Send Certificate [+ CertificateVerify]
          signature = Endpoint.sign_finished(
            digest:,
            finished_key: key_schedule.client_finished_key,
            hash: @transcript.hash(digest, EOED)
          )
          cf = send_finished(signature, hs_wcipher)
          @transcript[CF] = [cf, cf.serialize]
          @connection.ap_wcipher = Endpoint.gen_cipher(
            @cipher_suite,
            key_schedule.client_application_write_key,
            key_schedule.client_application_write_iv
          )
          @connection.alert_wcipher = @connection.ap_wcipher
          sslkeylogfile&.write_client_traffic_secret_0(
            @transcript[CH].first.random,
            key_schedule.client_application_traffic_secret
          )
          @connection.ap_rcipher = Endpoint.gen_cipher(
            @cipher_suite,
            key_schedule.server_application_write_key,
            key_schedule.server_application_write_iv
          )
          sslkeylogfile&.write_server_traffic_secret_0(
            @transcript[CH].first.random,
            key_schedule.server_application_traffic_secret
          )
          @exporter_secret = key_schedule.exporter_secret
          @resumption_secret = key_schedule.resumption_secret
          @connection.state = ClientState::CONNECTED
        when ClientState::CONNECTED
          logger.debug('ClientState::CONNECTED')

          @connection.send_alert(:ech_required) \
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

    # @raise [TTTLS13::Error::ConfigError]
    #
    # @return [String]
    def read
      nst_process = method(:process_new_session_ticket)
      @connection.read(nst_process)
    end

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

      @connection.write(binary)
    end

    # return [Boolean]
    def eof?
      @connection.eof?
    end

    def close
      @connection.close
    end

    # @return [TTTLS13::CipherSuite, nil]
    def negotiated_cipher_suite
      @cipher_suite
    end

    # @return [TTTLS13::NamedGroup, nil]
    def negotiated_named_group
      @named_group
    end

    # @return [TTTLS13::SignatureScheme, nil]
    def negotiated_signature_scheme
      @signature_scheme
    end

    # @return [String]
    def negotiated_alpn
      @alpn
    end

    # @param label [String]
    # @param context [String]
    # @param key_length [Integer]
    #
    # @return [String, nil]
    def exporter(label, context, key_length)
      return nil if @exporter_secret.nil? || @cipher_suite.nil?

      digest = CipherSuite.digest(@cipher_suite)
      Endpoint.exporter(@exporter_secret, digest, label, context, key_length)
    end

    # @param binary [String]
    #
    # @raise [TTTLS13::Error::ConfigError]
    def early_data(binary)
      raise Error::ConfigError unless @connection.state == INITIAL && use_psk?

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
      %i[
        ticket
        resumption_secret
        psk_cipher_suite
        ticket_nonce
        ticket_age_add
        ticket_timestamp
      ].all? { |sy| !@settings[sy].nil? }
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
        cipher:
      )
      @connection.send_record(ap_record)
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
    # @return [TTTLS13::SharedSecret]
    # rubocop: disable Metrics/AbcSize
    # rubocop: disable Metrics/MethodLength
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
      key_share, shared_secret \
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

      [exs, shared_secret]
    end

    # rubocop: enable Metrics/AbcSize
    # rubocop: enable Metrics/MethodLength
    # @param extensions [TTTLS13::Message::Extensions]
    # @param binder_key [String, nil]
    #
    # @return [TTTLS13::Message::ClientHello] outer
    # @return [TTTLS13::Message::ClientHello] inner
    # @return [TTTLS13::EchState]
    # rubocop: disable Metrics/MethodLength
    def send_client_hello(extensions, binder_key = nil)
      ch = Message::ClientHello.new(
        cipher_suites: CipherSuites.new(@settings[:cipher_suites]),
        extensions:
      )

      # encrypted_client_hello
      inner = nil # TTTLS13::Message::ClientHello
      if use_ech?
        inner = ch
        inner_ech = Message::Extension::ECHClientHello.new_inner
        inner.extensions[Message::ExtensionType::ENCRYPTED_CLIENT_HELLO] \
          = inner_ech
        ch, inner, ech_state = Ech.offer_ech(
          inner,
          @settings[:ech_config],
          method(:select_ech_hpke_cipher_suite)
        )
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
          ch:,
          binder_key:
        )

        if use_ech?
          sign_grease_psk_binder(
            ch_outer: ch,
            inner_pks: inner.extensions[Message::ExtensionType::PRE_SHARED_KEY]
          )
        end
      end

      @connection.send_handshakes(Message::ContentType::HANDSHAKE, [ch],
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
    def sign_psk_binder(ch:, binder_key:, ch1: nil, hrr: nil)
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

      psk.offered_psks.binders[0] = Endpoint.sign_psk_binder(
        ch1:,
        hrr:,
        ch:,
        binder_key:,
        digest:
      )
    end

    # @param ch1 [TTTLS13::Message::ClientHello]
    # @param hrr [TTTLS13::Message::ServerHello]
    # @param ch_outer [TTTLS13::Message::ClientHello]
    # @param inner_psk [Message::Extension::PreSharedKey]
    # @param binder_key [String]
    #
    # @return [String]
    def sign_grease_psk_binder(ch_outer:, inner_psk:, binder_key:, ch1: nil,
                               hrr: nil)
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
            identity:,
            obfuscated_ticket_age: ota
          )],
          binders: placeholder_binders
        )
      )
      ch_outer.extensions[Message::ExtensionType::PRE_SHARED_KEY] = psk

      psk.offered_psks.binders[0] = Endpoint.sign_psk_binder(
        ch1:,
        hrr:,
        ch: ch_outer,
        binder_key:,
        digest:
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
    # @return [TTTLS13::SharedSecret]
    def gen_newch_extensions(ch1, hrr)
      exs = Message::Extensions.new
      # key_share
      if hrr.extensions.include?(Message::ExtensionType::KEY_SHARE)
        group = hrr.extensions[Message::ExtensionType::KEY_SHARE]
                   .key_share_entry.first.group
        key_share, shared_secret \
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

      [new_exs, shared_secret]
    end

    # https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
    #
    # @param ch1 [TTTLS13::Message::ClientHello]
    # @param hrr [TTTLS13::Message::ServerHello]
    # @param extensions [TTTLS13::Message::Extensions]
    # @param binder_key [String, nil]
    # @param ech_state [TTTLS13::EchState]
    #
    # @return [TTTLS13::Message::ClientHello] outer
    # @return [TTTLS13::Message::ClientHello] inner
    # rubocop: disable Metrics/AbcSize
    # rubocop: disable Metrics/MethodLength
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
        extensions:
      )

      # encrypted_client_hello
      if use_ech? && ech_state.nil?
        # If sending a second ClientHello in response to a HelloRetryRequest,
        # the client copies the entire "encrypted_client_hello" extension from
        # the first ClientHello.
        #
        # https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-17#section-6.2-3
        inner = ch.clone
        ch.extensions[Message::ExtensionType::ENCRYPTED_CLIENT_HELLO] \
          = ch1.extensions[Message::ExtensionType::ENCRYPTED_CLIENT_HELLO]
      elsif use_ech?
        ch, inner = Ech.offer_new_ech(ch, ech_state)
      end

      # pre_shared_key
      #
      # Updating the "pre_shared_key" extension if present by recomputing
      # the "obfuscated_ticket_age" and binder values.
      if ch1.extensions.include?(Message::ExtensionType::PRE_SHARED_KEY)
        sign_psk_binder(ch1:, hrr:, ch:, binder_key:)

        if use_ech?
          # it MUST also copy the "psk_key_exchange_modes" from the
          # ClientHelloInner into the ClientHelloOuter.
          ch.extensions[Message::ExtensionType::PSK_KEY_EXCHANGE_MODES] \
            = inner.extensions[Message::ExtensionType::PSK_KEY_EXCHANGE_MODES]
          # it MUST also include the "early_data" extension in ClientHelloOuter.
          ch.extensions[Message::ExtensionType::EARLY_DATA] \
            = inner.extensions[Message::ExtensionType::EARLY_DATA]
          sign_grease_psk_binder(
            ch1:,
            hrr:,
            ch_outer: ch,
            inner_psk: inner.extensions[Message::ExtensionType::PRE_SHARED_KEY],
            binder_key:
          )
        end
      end

      @connection.send_handshakes(Message::ContentType::HANDSHAKE, [ch],
                                  Cryptograph::Passer.new)

      [ch, inner]
    end
    # rubocop: enable Metrics/AbcSize
    # rubocop: enable Metrics/MethodLength

    # @raise [TTTLS13::Error::ErrorAlerts]
    #
    # @return [TTTLS13::Message::ServerHello]
    # @return [String]
    def recv_server_hello
      sh, orig_msg = @connection.recv_message(
        receivable_ccs: true,
        cipher: Cryptograph::Passer.new
      )
      @connection.terminate(:unexpected_message) \
        unless sh.is_a?(Message::ServerHello)

      [sh, orig_msg]
    end

    # @param cipher [TTTLS13::Cryptograph::Aead]
    #
    # @raise [TTTLS13::Error::ErrorAlerts]
    #
    # @return [TTTLS13::Message::EncryptedExtensions]
    # @return [String]
    def recv_encrypted_extensions(cipher)
      ee, orig_msg \
        = @connection.recv_message(receivable_ccs: true, cipher:)
      @connection.terminate(:unexpected_message) \
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
      ct, orig_msg \
        = @connection.recv_message(receivable_ccs: true, cipher:)
      @connection.terminate(:unexpected_message) \
        unless ct.is_a?(Message::Certificate)

      [ct, orig_msg]
    end

    # @param cipher [TTTLS13::Cryptograph::Aead]
    #
    # @raise [TTTLS13::Error::ErrorAlerts]
    #
    # @return [TTTLS13::Message::CertificateVerify]
    # @return [String]
    def recv_certificate_verify(cipher)
      cv, orig_msg \
        = @connection.recv_message(receivable_ccs: true, cipher:)
      @connection.terminate(:unexpected_message) \
        unless cv.is_a?(Message::CertificateVerify)

      [cv, orig_msg]
    end

    # @param cipher [TTTLS13::Cryptograph::Aead]
    #
    # @raise [TTTLS13::Error::ErrorAlerts]
    #
    # @return [TTTLS13::Message::Finished]
    # @return [String]
    def recv_finished(cipher)
      sf, orig_msg \
        = @connection.recv_message(receivable_ccs: true, cipher:)
      @connection.terminate(:unexpected_message) \
        unless sf.is_a?(Message::Finished)

      [sf, orig_msg]
    end

    # @param cipher [TTTLS13::Cryptograph::Aead]
    #
    # @return [TTTLS13::Message::Finished]
    def send_finished(signature, cipher)
      cf = Message::Finished.new(signature)
      @connection.send_handshakes(
        Message::ContentType::APPLICATION_DATA,
        [cf],
        cipher
      )

      cf
    end

    # @param cipher [TTTLS13::Cryptograph::Aead]
    #
    # @return [TTTLS13::Message::EndOfEarlyData]
    def send_eoed(cipher)
      eoed = Message::EndOfEarlyData.new
      @connection.send_handshakes(
        Message::ContentType::APPLICATION_DATA,
        [eoed],
        cipher
      )

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

      return :certificate_unknown unless Endpoint.trusted_certificate?(
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

      Endpoint.verified_certificate_verify?(
        public_key:,
        signature_scheme:,
        signature:,
        context: 'TLS 1.3, server CertificateVerify',
        hash:
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
      rms = @resumption_secret
      cs = @cipher_suite
      @settings[:process_new_session_ticket]&.call(nst, rms, cs)
    end

    # @param cid [OpenSSL::OCSP::CertificateId]
    #
    # @return [OpenSSL::OCSP::Request]
    def gen_ocsp_request(cid)
      ocsp_request = OpenSSL::OCSP::Request.new
      ocsp_request.add_certid(cid)
      ocsp_request.add_nonce
      ocsp_request
    end
  end
  # rubocop: enable Metrics/ClassLength
end
