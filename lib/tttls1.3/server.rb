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
  private_constant :DEFAULT_SP_CIPHER_SUITES

  DEFAULT_SP_SIGNATURE_ALGORITHMS = [
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
  private_constant :DEFAULT_SP_SIGNATURE_ALGORITHMS

  DEFAULT_SP_NAMED_GROUP_LIST = [
    NamedGroup::SECP256R1,
    NamedGroup::SECP384R1,
    NamedGroup::SECP521R1
  ].freeze
  private_constant :DEFAULT_SP_NAMED_GROUP_LIST

  DEFAULT_SERVER_SETTINGS = {
    crt_file: nil,
    key_file: nil,
    cipher_suites: DEFAULT_SP_CIPHER_SUITES,
    signature_algorithms: DEFAULT_SP_SIGNATURE_ALGORITHMS,
    supported_groups: DEFAULT_SP_NAMED_GROUP_LIST,
    loglevel: Logger::WARN
  }.freeze
  private_constant :DEFAULT_SERVER_SETTINGS

  # rubocop: disable Metrics/ClassLength
  class Server < Connection
    # @param socket [Socket]
    # @param settings [Hash]
    def initialize(socket, **settings)
      super(socket)

      @endpoint = :server
      @settings = DEFAULT_SERVER_SETTINGS.merge(settings)
      logger.level = @settings[:loglevel]

      raise Error::ConfigError unless valid_settings?
      return if @settings[:crt_file].nil?

      crt_str = File.read(@settings[:crt_file])
      @crt = OpenSSL::X509::Certificate.new(crt_str) # TODO: spki rsassaPss
      klass = @crt.public_key.class
      @key = klass.new(File.read(@settings[:key_file]))
      raise Error::ConfigError unless @crt.check_private_key(@key)
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

          ch = @transcript[CH] = recv_client_hello
          terminate(:illegal_parameter) unless ch.only_appearable_extensions?
          @state = ServerState::RECVD_CH
        when ServerState::RECVD_CH
          logger.debug('ServerState::RECVD_CH')

          # support only TLS 1.3
          terminate(:protocol_version) unless negotiated_tls_1_3?

          # validate/select parameters
          terminamte(:illegal_parameter) unless valid_ch_compression_methods?
          terminate(:illegal_parameter) unless valid_ch_key_share?
          terminate(:unrecognized_name) unless recognized_server_name?
          @cipher_suite = select_cipher_suite
          @named_group = select_named_group
          @signature_scheme = select_signature_scheme
          terminate(:handshake_failure) \
            if @cipher_suite.nil? || @signature_scheme.nil?

          # send HRR
          if @named_group.nil?
            @transcript[CH1] = @transcript.delete(CH)
            @transcript[HRR] = send_hello_retry_request
            @state = ServerState::START
            next
          end
          @state = ServerState::NEGOTIATED
        when ServerState::NEGOTIATED
          logger.debug('ServerState::NEGOTIATED')

          exs, @priv_key = gen_sh_extensions
          @transcript[SH] = send_server_hello(exs)
          send_ccs # compatibility mode

          # generate shared secret
          ke = @transcript[CH].extensions[Message::ExtensionType::KEY_SHARE]
                             &.key_share_entry
                             &.find { |e| e.group == @named_group }
                             &.key_exchange
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

          cf = @transcript[CF] = recv_finished
          digest = CipherSuite.digest(@cipher_suite)
          vf = verified_finished?(
            finished: cf,
            digest: digest,
            finished_key: @key_schedule.client_finished_key,
            hash: @transcript.hash(digest, EOED)
          )
          terminate(:decrypt_error) unless vf
          @write_cipher = gen_cipher(@cipher_suite,
                                     @key_schedule.server_application_write_key,
                                     @key_schedule.server_application_write_iv)
          @read_cipher = gen_cipher(@cipher_suite,
                                    @key_schedule.client_application_write_key,
                                    @key_schedule.client_application_write_iv)
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

    # @return [Boolean]
    def valid_settings?
      mod = CipherSuite
      defined = mod.constants.map { |c| mod.const_get(c) }
      return false unless (@settings[:cipher_suites] - defined).empty?

      mod = SignatureScheme
      defined = mod.constants.map { |c| mod.const_get(c) }
      return false unless (@settings[:signature_algorithms] - defined).empty?

      mod = NamedGroup
      defined = mod.constants.map { |c| mod.const_get(c) }
      return false unless (@settings[:supported_groups] - defined).empty?

      true
    end

    # @raise [TTTLS13::Error::ErrorAlerts]
    #
    # @return [TTTLS13::Message::ClientHello]
    def recv_client_hello
      ch = recv_message
      terminate(:unexpected_message) unless ch.is_a?(Message::ClientHello)

      ch
    end

    # @param exs [TTTLS13::Message::Extensions]
    #
    # @return [TTTLS13::Message::ServerHello]
    def send_server_hello(exs)
      ch_session_id = @transcript[CH].legacy_session_id
      sh = Message::ServerHello.new(
        legacy_session_id_echo: ch_session_id,
        cipher_suite: @cipher_suite,
        extensions: exs
      )
      send_handshakes(Message::ContentType::HANDSHAKE, [sh], @write_cipher)

      sh
    end

    # @return [TTTLS13::Message::ServerHello]
    def send_hello_retry_request
      exs = []
      # supported_versions
      exs << Message::Extension::SupportedVersions.new(
        msg_type: Message::HandshakeType::SERVER_HELLO
      )

      # key_share
      ch1 = @transcript[CH1]
      sp_groups = ch1.extensions[Message::ExtensionType::SUPPORTED_GROUPS]
                    &.named_group_list || []
      ks_groups = ch1.extensions[Message::ExtensionType::KEY_SHARE]
                    &.key_share_entry&.map(&:group) || []
      ksg = sp_groups.find do |g|
        !ks_groups.include?(g) && @settings[:supported_groups].include?(g)
      end

      # TODO: cookie
      exs << Message::Extension::KeyShare.gen_hrr_key_share(ksg)

      sh = Message::ServerHello.new(
        random: Message::HRR_RANDOM,
        legacy_session_id_echo: ch1.legacy_session_id,
        cipher_suite: @cipher_suite,
        extensions: Message::Extensions.new(exs)
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

      digest = CipherSuite.digest(@cipher_suite)
      signature = sign_certificate_verify(
        key: @key,
        signature_scheme: @signature_scheme,
        hash: @transcript.hash(digest, CT)
      )
      Message::CertificateVerify.new(signature_scheme: @signature_scheme,
                                     signature: signature)
    end

    # @return [TTTLS13::Message::Finished]
    def gen_finished
      digest = CipherSuite.digest(@cipher_suite)
      signature = sign_finished(
        digest: digest,
        finished_key: @key_schedule.server_finished_key,
        hash: @transcript.hash(digest, CV)
      )

      Message::Finished.new(signature)
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
    # @return [OpenSSL::PKey::EC.$Object]
    def gen_sh_extensions
      exs = []
      # supported_versions: only TLS 1.3
      exs << Message::Extension::SupportedVersions.new(
        msg_type: Message::HandshakeType::SERVER_HELLO
      )

      # key_share
      key_share, priv_key \
                 = Message::Extension::KeyShare.gen_sh_key_share(@named_group)
      exs << key_share

      [Message::Extensions.new(exs), priv_key]
    end

    # @return [TTTLS13::Message::Extensions]
    def gen_ee_extensions
      exs = []

      # server_name
      exs << Message::Extension::ServerName.new('') \
        if @transcript[CH].extensions
                          .include?(Message::ExtensionType::SERVER_NAME)

      # supported_groups
      exs \
      << Message::Extension::SupportedGroups.new(@settings[:supported_groups])

      Message::Extensions.new(exs)
    end

    # @param key [OpenSSL::PKey::PKey]
    # @param signature_scheme [TTTLS13::SignatureScheme]
    # @param hash [String]
    #
    # @return [String]
    def sign_certificate_verify(key:, signature_scheme:, hash:)
      do_sign_certificate_verify(
        key: key,
        signature_scheme: signature_scheme,
        context: 'TLS 1.3, server CertificateVerify',
        hash: hash
      )
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

    # @return [TTTLS13::NamedGroup, nil]
    def select_named_group
      ks_groups = @transcript[CH].extensions[Message::ExtensionType::KEY_SHARE]
                                &.key_share_entry&.map(&:group) || []

      ks_groups.find do |g|
        @settings[:supported_groups].include?(g)
      end
    end

    # @return [TTTLS13::SignatureScheme, nil]
    def select_signature_scheme
      algorithms \
      = @transcript[CH].extensions[Message::ExtensionType::SIGNATURE_ALGORITHMS]
                      &.supported_signature_algorithms || []

      do_select_signature_algorithms(algorithms, @crt).find do |ss|
        @settings[:signature_algorithms].include?(ss)
      end
    end

    # @return [Boolean]
    def valid_ch_compression_methods?
      @transcript[CH].legacy_compression_methods == ["\x00"]
    end

    # @return [Boolean]
    def recognized_server_name?
      server_name \
      = @transcript[CH].extensions[Message::ExtensionType::SERVER_NAME]
                      &.server_name

      return true if server_name.nil?

      matching_san?(@crt, server_name)
    end

    # @return [Boolean]
    def valid_ch_key_share?
      ks = @transcript[CH].extensions[Message::ExtensionType::KEY_SHARE]
      ks_groups = ks&.key_share_entry&.map(&:group) || []
      sg = @transcript[CH].extensions[Message::ExtensionType::SUPPORTED_GROUPS]
      sp_groups = sg&.named_group_list || []

      # Each KeyShareEntry value MUST correspond to a group offered in the
      # "supported_groups" extension and MUST appear in the same order.
      #
      # Clients MUST NOT offer multiple KeyShareEntry values for the same group.
      (ks_groups - sp_groups).empty? &&
        sp_groups.filter { |g| ks_groups.include?(g) } == ks_groups &&
        ks_groups.uniq == ks_groups
    end
  end
  # rubocop: enable Metrics/ClassLength
end
