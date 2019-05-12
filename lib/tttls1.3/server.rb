# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  using Refinements
  module ServerState
    # initial value is 0, eof value is -1
    START         = 1
    RECVD_CH      = 2
    NEGOTIATED    = 3
    WAIT_EOED     = 4
    WAIT_FLIGHT2  = 5
    WAIT_CERT     = 6
    WAIT_CV       = 7
    WAIT_FINISHED = 8
    CONNECTED     = 9
  end

  DEFAULT_SP_CIPHER_SUITES = [
    CipherSuite::TLS_AES_256_GCM_SHA384,
    CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
    CipherSuite::TLS_AES_128_GCM_SHA256
  ].freeze

  DEFAULT_SP_SIGNATURE_ALGORITHMS = [
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

  DEFAULT_SP_NAMED_GROUP_LIST = [
    Message::Extension::NamedGroup::SECP256R1,
    Message::Extension::NamedGroup::SECP384R1,
    Message::Extension::NamedGroup::SECP521R1
  ].freeze

  DEFAULT_SERVER_SETTINGS = {
    crt_file: nil,
    key_file: nil,
    cipher_suites: DEFAULT_SP_CIPHER_SUITES,
    signature_algorithms: DEFAULT_SP_SIGNATURE_ALGORITHMS,
    supported_groups: DEFAULT_SP_NAMED_GROUP_LIST,
    loglevel: Logger::WARN
  }.freeze

  # rubocop: disable Metrics/ClassLength
  class Server < Connection
    # @param socket [Socket]
    # @param settings [Hash]
    def initialize(socket, **settings)
      super(socket)

      @endpoint = :server
      @settings = DEFAULT_SERVER_SETTINGS.merge(settings)
      logger.level = @settings[:loglevel]

      # TODO: valid_settings?

      return if @settings[:crt_file].nil?

      crt_str = File.read(@settings[:crt_file])
      @crt = OpenSSL::X509::Certificate.new(crt_str)
      klass = @crt.public_key.class
      @key = klass.new(File.read(@settings[:key_file]))
    end

    # NOTE:
    #                              START <-----+
    #               Recv ClientHello |         | Send HelloRetryRequest
    #                                v         |
    #                             RECVD_CH ----+
    #                                | Select parameters
    #                                v
    #                             NEGOTIATED
    #                                | Send ServerHello
    #                                | K_send = handshake
    #                                | Send EncryptedExtensions
    #                                | [Send CertificateRequest]
    # Can send                       | [Send Certificate + CertificateVerify]
    # app data                       | Send Finished
    # after   -->                    | K_send = application
    # here                  +--------+--------+
    #              No 0-RTT |                 | 0-RTT
    #                       |                 |
    #   K_recv = handshake  |                 | K_recv = early data
    # [Skip decrypt errors] |    +------> WAIT_EOED -+
    #                       |    |       Recv |      | Recv EndOfEarlyData
    #                       |    | early data |      | K_recv = handshake
    #                       |    +------------+      |
    #                       |                        |
    #                       +> WAIT_FLIGHT2 <--------+
    #                                |
    #                       +--------+--------+
    #               No auth |                 | Client auth
    #                       |                 |
    #                       |                 v
    #                       |             WAIT_CERT
    #                       |        Recv |       | Recv Certificate
    #                       |       empty |       v
    #                       | Certificate |    WAIT_CV
    #                       |             |       | Recv
    #                       |             v       | CertificateVerify
    #                       +-> WAIT_FINISHED <---+
    #                                | Recv Finished
    #                                | K_recv = application
    #                                v
    #                            CONNECTED
    #
    # https://tools.ietf.org/html/rfc8446#appendix-A.2
    #
    # rubocop: disable Metrics/AbcSize
    # rubocop: disable Metrics/BlockLength
    # rubocop: disable Metrics/CyclomaticComplexity
    # rubocop: disable Metrics/MethodLength
    # rubocop: disable Metrics/PerceivedComplexity
    def accept
      @state = ServerState::START
      loop do
        case @state
        when ServerState::START
          logger.debug('ServerState::START')

          @transcript[CH] = recv_client_hello
          @state = ServerState::RECVD_CH
        when ServerState::RECVD_CH
          logger.debug('ServerState::RECVD_CH')

          # support only TLS 1.3
          terminate(:protocol_version) unless negotiated_tls_1_3?

          # validate/select parameters
          terminamte(:illegal_parameter) unless valid_ch_compression_methods?
          @cipher_suite = select_cipher_suite
          @named_group = select_named_group
          @signature_scheme = select_signature_scheme
          terminate(:handshake_failure) \
            if @cipher_suite.nil? || @named_group.nil? || @signature_scheme.nil?

          @state = ServerState::NEGOTIATED
        when ServerState::NEGOTIATED
          logger.debug('ServerState::NEGOTIATED')

          @transcript[SH] = send_server_hello

          # generate shared secret
          ke = @transcript[CH].extensions[Message::ExtensionType::KEY_SHARE]
                              .key_share_entry
                              .find { |e| e.group == @named_group }.key_exchange
          shared_secret = gen_shared_secret(ke, @priv_key, @named_group)
          @key_schedule = KeySchedule.new(psk: @psk,
                                          shared_secret: shared_secret,
                                          cipher_suite: @cipher_suite,
                                          transcript: @transcript)
          @write_cipher = gen_cipher(@cipher_suite,
                                     @key_schedule.server_handshake_write_key,
                                     @key_schedule.server_handshake_write_iv)
          @read_cipher = gen_cipher(@cipher_suite,
                                    @key_schedule.client_handshake_write_key,
                                    @key_schedule.client_handshake_write_iv)
          @state = ServerState::WAIT_FLIGHT2
        when ServerState::WAIT_EOED
          logger.debug('ServerState::WAIT_EOED')
        when ServerState::WAIT_FLIGHT2
          logger.debug('ServerState::WAIT_FLIGHT2')

          ee = @transcript[EE] = gen_encrypted_extensions
          # TODO: [Send CertificateRequest]
          ct = @transcript[CT] = gen_certificate
          cv = @transcript[CV] = gen_certificate_verify
          sf = @transcript[SF] = gen_finished
          send_server_parameters([ee, ct, cv, sf])
          @state = ServerState::WAIT_FINISHED
        when ServerState::WAIT_CERT
          logger.debug('ServerState::WAIT_CERT')
        when ServerState::WAIT_CV
          logger.debug('ServerState::WAIT_CV')
        when ServerState::WAIT_FINISHED
          logger.debug('ServerState::WAIT_FINISHED')

          @transcript[CF] = recv_finished
          @state = ServerState::CONNECTED
        when ServerState::CONNECTED
          logger.debug('ServerState::CONNECTED')
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

    # @raise [TTTLS13::Error::ErrorAlerts]
    #
    # @return [TTTLS13::Message::ClientHello]
    def recv_client_hello
      ch = recv_message
      terminate(:unexpected_message) unless ch.is_a?(Message::ClientHello)

      ch
    end

    # @return [TTTLS13::Message::ServerHello]
    def send_server_hello
      ch_session_id = @transcript[CH].legacy_session_id
      sh = Message::ServerHello.new(
        legacy_session_id_echo: ch_session_id,
        cipher_suite: @cipher_suite,
        extensions: gen_sh_extensions
      )
      send_handshakes(Message::ContentType::HANDSHAKE, [sh], @write_cipher)

      sh
    end

    # @param messages [Array of TTTLS13::Message::$Object]
    #
    # @return [Array of TTTLS13::Message::$Object]
    def send_server_parameters(messages)
      send_handshakes(Message::ContentType::APPLICATION_DATA,
                      messages.reject(&:nil?),
                      @write_cipher)

      messages
    end

    # @return [TTTLS13::Message::EncryptedExtensions]
    def gen_encrypted_extensions
      Message::EncryptedExtensions.new(gen_ee_extensions)
    end

    # @return [TTTLS13::Message::Certificate, nil]
    def gen_certificate
      return nil if @crt.nil?

      ce = Message::CertificateEntry.new(@crt)
      Message::Certificate.new(certificate_list: [ce])
    end

    # @return [TTTLS13::Message::CertificateVerify, nil]
    def gen_certificate_verify
      return nil if @key.nil?

      Message::CertificateVerify.new(signature_scheme: @signature_scheme,
                                     signature: sign_certificate_verify)
    end

    # @return [TTTLS13::Message::Finished]
    def gen_finished
      Message::Finished.new(sign_finished)
    end

    # @raise [TTTLS13::Error::ErrorAlerts]
    #
    # @return [TTTLS13::Message::Finished]
    def recv_finished
      cf = recv_message
      terminate(:unexpected_message) unless cf.is_a?(Message::Finished)

      cf
    end

    # @return [TTTLS13::Message::Extensions]
    def gen_sh_extensions
      exs = []
      # supported_versions: only TLS 1.3
      exs << Message::Extension::SupportedVersions.new(
        msg_type: Message::HandshakeType::SERVER_HELLO
      )

      # key_share
      key_share, @priv_key \
                 = Message::Extension::KeyShare.gen_sh_key_share(@named_group)
      exs << key_share
      Message::Extensions.new(exs)
    end

    # @return [TTTLS13::Message::Extensions]
    def gen_ee_extensions
      exs = []

      # server_name
      exs << ServerName.new('') \
        if @transcript[CH].extensions
                          .include?(Message::ExtensionType::SERVER_NAME)

      # supported_groups
      exs \
      << Message::Extension::SupportedGroups.new(@settings[:supported_groups])

      Message::Extensions.new(exs)
    end

    # @return [String]
    def sign_certificate_verify
      context = 'TLS 1.3, server CertificateVerify'
      do_sign_certificate_verify(private_key: @key,
                                 signature_scheme: @signature_scheme,
                                 context: context,
                                 handshake_context_end: CT)
    end

    # @return [String]
    def sign_finished
      digest = CipherSuite.digest(@cipher_suite)
      finished_key = @key_schedule.server_finished_key
      do_sign_finished(digest: digest,
                       finished_key: finished_key,
                       handshake_context_end: CV)
    end

    # @return [Boolean]
    def negotiated_tls_1_3?
      ch = @transcript[CH]
      ch_lv = ch.legacy_version
      ch_sv = ch.extensions[Message::ExtensionType::SUPPORTED_VERSIONS]
                &.versions || []

      ch_lv == Message::ProtocolVersion::TLS_1_2 &&
        ch_sv.include?(Message::ProtocolVersion::TLS_1_3)
    end

    # @return [TTTLS13::CipherSuite, nil]
    def select_cipher_suite
      @transcript[CH].cipher_suites.find do |cs|
        @settings[:cipher_suites].include?(cs)
      end
    end

    # @return [TTTLS13::Message::Extension::NamedGroup, nil]
    def select_named_group
      groups \
      = @transcript[CH].extensions[Message::ExtensionType::SUPPORTED_GROUPS]
                       &.named_group_list || []
      groups.find do |sg|
        @settings[:supported_groups].include?(sg)
      end
    end

    # @return [TTTLS13::SignatureScheme, nil]
    def select_signature_scheme
      algorithms \
      = @transcript[CH].extensions[Message::ExtensionType::SIGNATURE_ALGORITHMS]
                       &.supported_signature_algorithms || []
      algorithms.find do |ss|
        @settings[:signature_algorithms].include?(ss)
        # TODO
        # 1. check @crt's signature_algorithm; rsaEncryption or rsassaPss
        # 2. check supported_groups if signature_algorithm uses ECDSA algorithms
      end
    end

    # @return [Boolean]
    def valid_ch_compression_methods?
      @transcript[CH].legacy_compression_methods == ["\x00"]
    end
  end
  # rubocop: enable Metrics/ClassLength
end
