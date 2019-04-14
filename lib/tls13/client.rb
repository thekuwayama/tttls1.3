# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
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
    supported_groups: DEFAULT_CH_NAMED_GROUP_LIST
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
    # https://tools.ietf.org/html/rfc8446#appendix-A
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
          send_client_hello
          @state = ClientState::WAIT_SH
        when ClientState::WAIT_SH
          sh = recv_server_hello
          terminate(:illegal_parameter) unless offered_legacy_version?
          terminate(:illegal_parameter) unless echoed_legacy_session_id?
          terminate(:illegal_parameter) unless offered_cipher_suite?
          terminate(:illegal_parameter) unless valid_compression_method?
          terminate(:unsupported_extension) \
            unless offered_ch_extensions?(sh.extensions)
          # only TLS 1.3
          terminate(:protocol_version) unless negotiated_tls_1_3?

          if sh.hrr?
            terminate(:unexpected_message) if received_2nd_hrr?

            @transcript[CH1] = @transcript.delete(CH)
            @transcript[HRR] = @transcript.delete(SH)
            @state = ClientState::START
            next
          end

          if @transcript.key?(HRR) && (neq_hrr_cipher_suite? ||
                                       neq_hrr_supported_versions?)
            terminate(:illegal_parameter)
          end

          @cipher_suite = sh.cipher_suite
          kse = sh.extensions[Message::ExtensionType::KEY_SHARE]
                  .key_share_entry.first
          key_exchange = kse.key_exchange
          group = kse.group
          priv_key = @priv_keys[group]
          shared_key = gen_shared_secret(key_exchange, priv_key, group)
          @key_schedule = KeySchedule.new(shared_secret: shared_key,
                                          cipher_suite: @cipher_suite,
                                          transcript: @transcript)

          @state = ClientState::WAIT_EE
        when ClientState::WAIT_EE
          ee = recv_encrypted_extensions
          terminate(:illegal_parameter) if ee.any_forbidden_extensions?
          terminate(:unsupported_extension) \
            unless offered_ch_extensions?(ee.extensions)

          rsl = ee.extensions[Message::ExtensionType::RECORD_SIZE_LIMIT]
          @send_record_size = rsl.record_size_limit unless rsl.nil?

          # TODO: Using PSK
          @state = ClientState::WAIT_CERT_CR
        when ClientState::WAIT_CERT_CR
          message = recv_message
          if message.msg_type == Message::HandshakeType::CERTIFICATE
            @transcript[CT] = ct = message
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
          ct = recv_certificate
          ct.certificate_list.map(&:extensions).each do |ex|
            terminate(:unsupported_extension) unless offered_ch_extensions?(ex)
          end

          terminate(:certificate_unknown) \
            unless certified_certificate?(ct.certificate_list,
                                          @settings[:ca_file], @hostname)

          @state = ClientState::WAIT_CV
        when ClientState::WAIT_CV
          recv_certificate_verify
          terminate(:decrypt_error) unless verify_certificate_verify
          @state = ClientState::WAIT_FINISHED
        when ClientState::WAIT_FINISHED
          recv_finished
          terminate(:decrypt_error) unless verify_finished
          send_ccs # compatibility mode
          # TODO: Send EndOfEarlyData
          # TODO: Send Certificate [+ CertificateVerify]
          send_finished
          @state = ClientState::CONNECTED
        when ClientState::CONNECTED
          break
        end
      end
    end
    # rubocop: enable Metrics/AbcSize
    # rubocop: enable Metrics/BlockLength
    # rubocop: enable Metrics/CyclomaticComplexity
    # rubocop: enable Metrics/MethodLength
    # rubocop: enable Metrics/PerceivedComplexity

    private

    DOWNGRADE_PROTECTION_TLS_1_2 = "\x44\x4F\x57\x4E\x47\x52\x44\x01"
    DOWNGRADE_PROTECTION_TLS_1_1 = "\x44\x4F\x57\x4E\x47\x52\x44\x00"

    # @return [TLS13::Message::Extensions]
    def gen_extensions
      exs = []
      # supported_versions: only TLS 1.3
      exs << Message::Extension::SupportedVersions.new(
        msg_type: Message::HandshakeType::CLIENT_HELLO
      )
      # signature_algorithms
      exs << Message::Extension::SignatureAlgorithms.new(
        @settings[:signature_algorithms]
      )
      # supported_groups
      groups = @settings[:supported_groups]
      exs << Message::Extension::SupportedGroups.new(groups)
      # key_share
      key_share, priv_keys \
                 = Message::Extension::KeyShare.gen_ch_key_share(groups)
      exs << key_share
      @priv_keys = priv_keys.merge(@priv_keys)
      # server_name
      exs << Message::Extension::ServerName.new(@hostname) \
        unless @hostname.nil? || @hostname.empty?
      # cookie
      #
      # When sending the new ClientHello, the client MUST copy the contents of
      # the extension received in the HelloRetryRequest into a "cookie"
      # extension in the new ClientHello.
      #
      # https://tools.ietf.org/html/rfc8446#section-4.2.2
      if @transcript.key?(HRR)
        exs << @transcript[HRR].extensions[Message::ExtensionType::COOKIE]
      end

      Message::Extensions.new(exs)
    end

    # @return [TLS13::Message::ClientHello]
    def send_client_hello
      ch = Message::ClientHello.new(
        cipher_suites: CipherSuites.new(@settings[:cipher_suites]),
        extensions: gen_extensions
      )
      send_handshakes(Message::ContentType::HANDSHAKE, [ch])
      @transcript[CH] = ch
    end

    # @raise [TLS13::Error::ErrorAlerts]
    #
    # @return [TLS13::Message::ServerHello]
    def recv_server_hello
      sh = recv_message
      terminate(:unexpected_message) unless sh.is_a?(Message::ServerHello)

      @transcript[SH] = sh
    end

    # @raise [TLS13::Error::ErrorAlerts]
    #
    # @return [TLS13::Message::EncryptedExtensions]
    def recv_encrypted_extensions
      ee = recv_message
      terminate(:unexpected_message) \
        unless ee.is_a?(Message::EncryptedExtensions)

      @transcript[EE] = ee
    end

    # @raise [TLS13::Error::ErrorAlerts]
    #
    # @return [TLS13::Message::Certificate]
    def recv_certificate
      ct = recv_message
      terminate(:unexpected_message) unless ct.is_a?(Message::Certificate)

      @transcript[CT] = ct
    end

    # @raise [TLS13::Error::ErrorAlerts]
    #
    # @return [TLS13::Message::CertificateVerify]
    def recv_certificate_verify
      cv = recv_message
      terminate(:unexpected_message) unless cv.is_a?(Message::CertificateVerify)

      @transcript[CV] = cv
    end

    # @raise [TLS13::Error::ErrorAlerts]
    #
    # @return [TLS13::Message::Finished]
    def recv_finished
      sf = recv_message
      terminate(:unexpected_message) unless sf.is_a?(Message::Finished)

      @transcript[SF] = sf
    end

    # @return [TLS13::Message::Finished]
    def send_finished
      cf = Message::Finished.new(sign_finished)
      send_handshakes(Message::ContentType::APPLICATION_DATA, [cf])
      @transcript[CF] = cf
    end

    # @return [Boolean]
    def verify_certificate_verify
      ct = @transcript[CT]
      certificate_pem = ct.certificate_list.first.cert_data.to_pem
      cv = @transcript[CV]
      signature_scheme = cv.signature_scheme
      signature = cv.signature
      context = 'TLS 1.3, server CertificateVerify'
      do_verify_certificate_verify(certificate_pem: certificate_pem,
                                   signature_scheme: signature_scheme,
                                   signature: signature,
                                   context: context,
                                   message_range: CH..CT)
    end

    # @return [String]
    def sign_finished
      digest = CipherSuite.digest(@cipher_suite)
      finished_key = @key_schedule.client_finished_key
      do_sign_finished(digest: digest,
                       finished_key: finished_key,
                       message_range: CH..EOED)
    end

    # @return [Boolean]
    def verify_finished
      digest = CipherSuite.digest(@cipher_suite)
      finished_key = @key_schedule.server_finished_key
      signature = @transcript[SF].verify_data
      do_verify_finished(digest: digest,
                         finished_key: finished_key,
                         message_range: CH..CV,
                         signature: signature)
    end

    # NOTE:
    # This implementation supports only TLS 1.3,
    # so negotiated_tls_1_3? assumes that it sent ClientHello with:
    #     1. supported_versions == ["\x03\x04"]
    #     2. legacy_versions == ["\x03\x03"]
    #
    # @raise [TLS13::Error::ErrorAlerts]
    #
    # @return [Boolean]
    def negotiated_tls_1_3?
      sh = @transcript[SH]
      sh_sv = sh.extensions[Message::ExtensionType::SUPPORTED_VERSIONS]
                &.versions
      sh_r8 = sh.random[-8..]
      if sh_sv&.first == Message::ProtocolVersion::TLS_1_3 &&
         sh_r8 != DOWNGRADE_PROTECTION_TLS_1_2 &&
         sh_r8 != DOWNGRADE_PROTECTION_TLS_1_1
        true
      elsif sh_sv.nil?
        false
      else
        terminate(:illegal_parameter)
      end
    end

    # @return [Boolean]
    def offered_legacy_version?
      @transcript[CH].legacy_version ==
        @transcript[SH].legacy_version
    end

    # @return [Boolean]
    def echoed_legacy_session_id?
      @transcript[CH].legacy_session_id ==
        @transcript[SH].legacy_session_id_echo
    end

    # @return [Boolean]
    def offered_cipher_suite?
      @transcript[CH].cipher_suites.include?(@transcript[SH].cipher_suite)
    end

    # @return [Boolean]
    def valid_compression_method?
      @transcript[SH].legacy_compression_method == "\x00"
    end

    # @param extensions [TLS13::Message::Extensions]
    # @param transcript_index [Integer]
    #
    # @return [Boolean]
    def offered_ch_extensions?(extensions, transcript_index = nil)
      keys = extensions.keys - @transcript[CH].extensions.keys
      keys -= [Message::ExtensionType::COOKIE] if transcript_index == HRR
      keys.empty?
    end

    # @return [Boolean]
    def received_2nd_hrr?
      @transcript.key?(HRR)
    end

    # @return [Boolean]
    def neq_hrr_cipher_suite?
      @transcript[HRR].cipher_suite != @transcript[SH].cipher_suite
    end

    # @return [Boolean]
    def neq_hrr_supported_versions?
      @transcript[HRR].extensions[Message::ExtensionType::SUPPORTED_VERSIONS] \
      != @transcript[SH].extensions[Message::ExtensionType::SUPPORTED_VERSIONS]
    end
  end
  # rubocop: enable Metrics/ClassLength
end
