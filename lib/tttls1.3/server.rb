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
    chain_files: nil,
    key_file: nil,
    cipher_suites: DEFAULT_SP_CIPHER_SUITES,
    signature_algorithms: DEFAULT_SP_SIGNATURE_ALGORITHMS,
    supported_groups: DEFAULT_SP_NAMED_GROUP_LIST,
    alpn: nil,
    process_ocsp_response: nil,
    compatibility_mode: true,
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

      @chain = @settings[:chain_files]&.map do |f|
        OpenSSL::X509::Certificate.new(File.read(f))
      end
      @chain ||= []
      ([@crt] + @chain).each_cons(2) do |cert, sign|
        raise Error::ConfigError unless cert.verify(sign.public_key)
      end
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
      transcript = Transcript.new
      key_schedule = nil # TTTLS13::KeySchedule
      priv_key = nil # OpenSSL::PKey::$Object
      hs_wcipher = nil # TTTLS13::Cryptograph::$Object
      hs_rcipher = nil # TTTLS13::Cryptograph::$Object

      @state = ServerState::START
      loop do
        case @state
        when ServerState::START
          logger.debug('ServerState::START')

          receivable_ccs = transcript.include?(CH1)
          ch, = transcript[CH] = recv_client_hello(receivable_ccs)

          # support only TLS 1.3
          terminate(:protocol_version) unless ch.negotiated_tls_1_3?

          # validate parameters
          terminate(:illegal_parameter) unless ch.appearable_extensions?
          terminamte(:illegal_parameter) \
            unless ch.legacy_compression_methods == ["\x00"]
          terminate(:illegal_parameter) unless ch.valid_key_share?
          terminate(:unrecognized_name) unless recognized_server_name?(ch, @crt)

          # alpn
          ch_alpn = ch.extensions[
            Message::ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION
          ]
          if !@settings[:alpn].nil? && !@settings[:alpn].empty? && !ch_alpn.nil?
            @alpn = ch_alpn.protocol_name_list
                           .find { |p| @settings[:alpn].include?(p) }

            terminate(:no_application_protocol) if @alpn.nil?
          end

          # record_size_limit
          ch_rsl = ch.extensions[Message::ExtensionType::RECORD_SIZE_LIMIT]
          @send_record_size = ch_rsl.record_size_limit unless ch_rsl.nil?

          @state = ServerState::RECVD_CH
        when ServerState::RECVD_CH
          logger.debug('ServerState::RECVD_CH')

          # select parameters
          ch, = transcript[CH]
          @cipher_suite = select_cipher_suite(ch)
          @named_group = select_named_group(ch)
          @signature_scheme = select_signature_scheme(ch, @crt)
          terminate(:handshake_failure) \
            if @cipher_suite.nil? || @signature_scheme.nil?

          # send HRR
          if @named_group.nil?
            ch1, = transcript[CH1] = transcript.delete(CH)
            hrr = send_hello_retry_request(ch1, @cipher_suite)
            transcript[HRR] = [hrr, hrr.serialize]
            @state = ServerState::START
            next
          end
          @state = ServerState::NEGOTIATED
        when ServerState::NEGOTIATED
          logger.debug('ServerState::NEGOTIATED')

          ch, = transcript[CH]
          extensions, priv_key = gen_sh_extensions(@named_group)
          sh = send_server_hello(
            extensions,
            @cipher_suite,
            ch.legacy_session_id
          )
          transcript[SH] = [sh, sh.serialize]
          send_ccs if @settings[:compatibility_mode]

          # generate shared secret
          ke = ch.extensions[Message::ExtensionType::KEY_SHARE]
                &.key_share_entry
                &.find { |e| e.group == @named_group }
                &.key_exchange
          shared_secret = gen_shared_secret(ke, priv_key, @named_group)
          key_schedule = KeySchedule.new(
            psk: @psk,
            shared_secret: shared_secret,
            cipher_suite: @cipher_suite,
            transcript: transcript
          )
          @alert_wcipher = hs_wcipher = gen_cipher(
            @cipher_suite,
            key_schedule.server_handshake_write_key,
            key_schedule.server_handshake_write_iv
          )
          hs_rcipher = gen_cipher(
            @cipher_suite,
            key_schedule.client_handshake_write_key,
            key_schedule.client_handshake_write_iv
          )
          @state = ServerState::WAIT_FLIGHT2
        when ServerState::WAIT_EOED
          logger.debug('ServerState::WAIT_EOED')
        when ServerState::WAIT_FLIGHT2
          logger.debug('ServerState::WAIT_FLIGHT2')

          ch, = transcript[CH]
          rsl = @send_record_size \
            if ch.extensions.include?(Message::ExtensionType::RECORD_SIZE_LIMIT)
          ee = gen_encrypted_extensions(ch, @alpn, rsl)
          transcript[EE] = [ee, ee.serialize]
          # TODO: [Send CertificateRequest]

          # status_request
          ocsp_response = fetch_ocsp_response \
            if ch.extensions.include?(Message::ExtensionType::STATUS_REQUEST)
          ct = gen_certificate(@crt, @chain, ocsp_response)
          transcript[CT] = [ct, ct.serialize]
          digest = CipherSuite.digest(@cipher_suite)
          hash = transcript.hash(digest, CT)
          cv = gen_certificate_verify(@key, @signature_scheme, hash)
          transcript[CV] = [cv, cv.serialize]
          finished_key = key_schedule.server_finished_key
          signature = sign_finished(
            digest: digest,
            finished_key: finished_key,
            hash: transcript.hash(digest, CV)
          )
          sf = Message::Finished.new(signature)
          transcript[SF] = [sf, sf.serialize]
          send_server_parameters([ee, ct, cv, sf], hs_wcipher)
          @state = ServerState::WAIT_FINISHED
        when ServerState::WAIT_CERT
          logger.debug('ServerState::WAIT_CERT')
        when ServerState::WAIT_CV
          logger.debug('ServerState::WAIT_CV')
        when ServerState::WAIT_FINISHED
          logger.debug('ServerState::WAIT_FINISHED')

          cf, = transcript[CF] = recv_finished(hs_rcipher)
          digest = CipherSuite.digest(@cipher_suite)
          verified = verified_finished?(
            finished: cf,
            digest: digest,
            finished_key: key_schedule.client_finished_key,
            hash: transcript.hash(digest, EOED)
          )
          terminate(:decrypt_error) unless verified
          @alert_wcipher = @ap_wcipher = gen_cipher(
            @cipher_suite,
            key_schedule.server_application_write_key,
            key_schedule.server_application_write_iv
          )
          @ap_rcipher = gen_cipher(
            @cipher_suite,
            key_schedule.client_application_write_key,
            key_schedule.client_application_write_iv
          )
          @exporter_master_secret = key_schedule.exporter_master_secret
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

    # @param receivable_ccs [Boolean]
    #
    # @raise [TTTLS13::Error::ErrorAlerts]
    #
    # @return [TTTLS13::Message::ClientHello]
    # @return [String]
    def recv_client_hello(receivable_ccs)
      ch, orig_msg = recv_message(
        receivable_ccs: receivable_ccs,
        cipher: Cryptograph::Passer.new
      )
      terminate(:unexpected_message) unless ch.is_a?(Message::ClientHello)

      [ch, orig_msg]
    end

    # @param extensions [TTTLS13::Message::Extensions]
    # @param cipher_suite [TTTLS13::CipherSuite]
    # @param session_id [String]
    #
    # @return [TTTLS13::Message::ServerHello]
    def send_server_hello(extensions, cipher_suite, session_id)
      sh = Message::ServerHello.new(
        legacy_session_id_echo: session_id,
        cipher_suite: cipher_suite,
        extensions: extensions
      )
      send_handshakes(Message::ContentType::HANDSHAKE, [sh],
                      Cryptograph::Passer.new)

      sh
    end

    # @param ch1 [TTTLS13::Message::ClientHello]
    # @param cipher_suite [TTTLS13::CipherSuite]
    #
    # @return [TTTLS13::Message::ServerHello]
    def send_hello_retry_request(ch1, cipher_suite)
      exs = Message::Extensions.new
      # supported_versions
      exs << Message::Extension::SupportedVersions.new(
        msg_type: Message::HandshakeType::SERVER_HELLO
      )

      # key_share
      sp_groups = ch1.extensions[Message::ExtensionType::SUPPORTED_GROUPS]
                    &.named_group_list || []
      ks_groups = ch1.extensions[Message::ExtensionType::KEY_SHARE]
                    &.key_share_entry&.map(&:group) || []
      ksg = sp_groups.find do |g|
        !ks_groups.include?(g) && @settings[:supported_groups].include?(g)
      end
      exs << Message::Extension::KeyShare.gen_hrr_key_share(ksg)

      # TODO: cookie

      sh = Message::ServerHello.new(
        random: Message::HRR_RANDOM,
        legacy_session_id_echo: ch1.legacy_session_id,
        cipher_suite: cipher_suite,
        extensions: exs
      )
      send_handshakes(Message::ContentType::HANDSHAKE, [sh],
                      Cryptograph::Passer.new)

      sh
    end

    # @param messages [Array of TTTLS13::Message::$Object]
    # @param cipher [TTTLS13::Cryptograph::Aead]
    #
    # @return [Array of TTTLS13::Message::$Object]
    def send_server_parameters(messages, cipher)
      send_handshakes(Message::ContentType::APPLICATION_DATA,
                      messages.reject(&:nil?), cipher)

      messages
    end

    # @param ch [TTTLS13::Message::ClientHello]
    # @param alpn [String, nil]
    # @param record_size_limit [Integer, nil]
    #
    # @return [TTTLS13::Message::EncryptedExtensions]
    def gen_encrypted_extensions(ch, alpn = nil, record_size_limit = nil)
      Message::EncryptedExtensions.new(
        gen_ee_extensions(ch, alpn, record_size_limit)
      )
    end

    # @param crt [OpenSSL::X509::Certificate]
    # @param chain [Array of OpenSSL::X509::Certificate]
    # @param ocsp_response [OpenSSL::OCSP::Response]
    #
    # @return [TTTLS13::Message::Certificate, nil]
    def gen_certificate(crt, chain = [], ocsp_response = nil)
      exs = Message::Extensions.new
      # status_request
      exs << Message::Extension::OCSPResponse.new(ocsp_response) \
        unless ocsp_response.nil?
      ces = [Message::CertificateEntry.new(crt, exs)] \
            + (chain || []).map { |c| Message::CertificateEntry.new(c) }
      Message::Certificate.new(certificate_list: ces)
    end

    # @param key [OpenSSL::PKey::PKey]
    # @param signature_scheme [TTTLS13::SignatureScheme]
    # @param hash [String]
    #
    # @return [TTTLS13::Message::CertificateVerify, nil]
    def gen_certificate_verify(key, signature_scheme, hash)
      signature = sign_certificate_verify(
        key: key,
        signature_scheme: signature_scheme,
        hash: hash
      )
      Message::CertificateVerify.new(signature_scheme: signature_scheme,
                                     signature: signature)
    end

    # @param cipher [TTTLS13::Cryptograph::Aead]
    #
    # @raise [TTTLS13::Error::ErrorAlerts]
    #
    # @return [TTTLS13::Message::Finished]
    # @return [String]
    def recv_finished(cipher)
      cf, orig_msg = recv_message(receivable_ccs: true, cipher: cipher)
      terminate(:unexpected_message) unless cf.is_a?(Message::Finished)

      [cf, orig_msg]
    end

    # @param named_group [TTTLS13::NamedGroup]
    #
    # @return [TTTLS13::Message::Extensions]
    # @return [OpenSSL::PKey::EC.$Object]
    def gen_sh_extensions(named_group)
      exs = Message::Extensions.new
      # supported_versions: only TLS 1.3
      exs << Message::Extension::SupportedVersions.new(
        msg_type: Message::HandshakeType::SERVER_HELLO
      )

      # key_share
      key_share, priv_key \
                 = Message::Extension::KeyShare.gen_sh_key_share(named_group)
      exs << key_share

      [exs, priv_key]
    end

    # @param ch [TTTLS13::Message::ClientHello]
    # @param alpn [String]
    # @param record_size_limit [Integer, nil]
    #
    # @return [TTTLS13::Message::Extensions]
    def gen_ee_extensions(ch, alpn, record_size_limit)
      exs = Message::Extensions.new

      # server_name
      exs << Message::Extension::ServerName.new('') \
        if ch.extensions.include?(Message::ExtensionType::SERVER_NAME)

      # supported_groups
      exs << Message::Extension::SupportedGroups.new(
        @settings[:supported_groups]
      )

      # alpn
      exs << Message::Extension::Alpn.new([alpn]) unless alpn.nil?

      # record_size_limit
      exs << Message::Extension::RecordSizeLimit.new(record_size_limit) \
        unless record_size_limit.nil?

      exs
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

    # @param ch [TTTLS13::Message::ClientHello]
    #
    # @return [TTTLS13::CipherSuite, nil]
    def select_cipher_suite(ch)
      ch.cipher_suites.find do |cs|
        @settings[:cipher_suites].include?(cs)
      end
    end

    # @param ch [TTTLS13::Message::ClientHello]
    #
    # @return [TTTLS13::NamedGroup, nil]
    def select_named_group(ch)
      ks_groups = ch.extensions[Message::ExtensionType::KEY_SHARE]
                   &.key_share_entry&.map(&:group) || []

      ks_groups.find do |g|
        @settings[:supported_groups].include?(g)
      end
    end

    # @param ch [TTTLS13::Message::ClientHello]
    # @param crt [OpenSSL::X509::Certificate]
    #
    # @return [TTTLS13::SignatureScheme, nil]
    def select_signature_scheme(ch, crt)
      algorithms = ch.extensions[Message::ExtensionType::SIGNATURE_ALGORITHMS]
                    &.supported_signature_algorithms || []

      do_select_signature_algorithms(algorithms, crt).find do |ss|
        @settings[:signature_algorithms].include?(ss)
      end
    end

    # @param ch [TTTLS13::Message::ClientHello]
    # @param crt [OpenSSL::X509::Certificate]
    #
    # @return [Boolean]
    def recognized_server_name?(ch, crt)
      server_name = ch.extensions[Message::ExtensionType::SERVER_NAME]
                     &.server_name
      return true if server_name.nil?

      matching_san?(crt, server_name)
    end

    # @return [OpenSSL::OCSP::Response, nil]
    def fetch_ocsp_response
      @settings[:process_ocsp_response]&.call
    end
  end
  # rubocop: enable Metrics/ClassLength
end
