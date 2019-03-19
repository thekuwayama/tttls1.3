# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  module ClientState
    START         = 1
    WAIT_SH       = 2
    WAIT_EE       = 3
    WAIT_CERT_CR  = 4
    WAIT_CERT     = 5
    WAIT_CV       = 6
    WAIT_FINISHED = 7
    CONNECTED     = 8
  end

  # rubocop: disable Metrics/ClassLength
  class Client < Connection
    # rubocop: disable all
    def connect
      state = ClientState::START
      loop do
        case state
        when ClientState::START
          send_client_hello
          state = ClientState::WAIT_SH
        when ClientState::WAIT_SH
          sh = recv_server_hello # TODO: Recv HelloRetryRequest
          # only P-256
          priv_key = @priv_keys[Message::Extension::NamedGroup::SECP256R1]
          pub_key = OpenSSL::PKey::EC::Point.new(
            OpenSSL::PKey::EC::Group.new('prime256v1'),
            OpenSSL::BN.new(sh.extensions[Message::ExtensionType::KEY_SHARE]
                              .first.key_exchange)
          )
          shared_secret = priv_key.dh_compute_key(pub_key)
          @cipher_suite = sh.cipher_suite
          @key_schedule = KeySchedule(shared_secret: shared_secret,
                                      cipher_suite: @cipher_suite)
          messages = [@transcript_messages[:CLIENT_HELLO],
                      @transcript_messages[:SERVER_HELLO]].map(&:serialize).join
          @read_cryptographer = Cryptograph::Aead.new(
            cipher_suite: @cipher_suite,
            key: @key_schedule.server_handshake_write_key(messages),
            nonce: @key_schedule.server_handshake_write_iv(messages),
            type: ContentType::HANDSHAKE
          )
          @write_cryptographer = Cryptograph::Aead.new(
            cipher_suite: @cipher_suite,
            key: @key_schedule.client_handshake_write_key(messages),
            nonce: @key_schedule.client_handshake_write_iv(messages),
            type: ContentType::HANDSHAKE
          )
          state = ClientState::WAIT_EE
        when ClientState::WAIT_EE
          recv_encrypted_extensions
          # TODO: get server parameters
          # TODO: Using PSK
          state = ClientState::WAIT_CR
        when ClientState::WAIT_CERT_CR
          message = recv_message
          if message.msg_type == Message::HandshakeType::CERTIFICATE
            @transcript_messages[:SERVER_CERTIFICATE] = message
            state = ClientState::WAIT_CV
          elsif message.msg_type == Message::HandshakeType::CERTIFICATE_REQUEST
            @transcript_messages[:CERTIFICATE_REQUEST] = message
            state = ClientState::WAIT_CERT
          else
            raise 'unexpected message'
          end
        when ClientState::WAIT_CERT
          recv_recv_certificate
          state = ClientState::WAIT_CV
        when ClientState::WAIT_CV
          recv_certificate_verify
          raise 'decrypt_error' unless verify_certificate_verify
          state = ClientState::WAIT_FINISHED
        when ClientState::WAIT_FINISHED
          recv_finished
          raise 'decrypt_error' unless verify_finished
          # TODO: Send EndOfEarlyData
          # TODO: Send Certificate [+ CertificateVerify]
          send_finished
          state = ClientState::CONNECTED
        when ClientState::CONNECTED
          break
        end
      end
    end
    # rubocop: enable all

    # @return [TLS13::Message::Extensions]
    # rubocop: disable Metrics/MethodLength
    def gen_extensions
      # supported_versions: TLS_1_3
      supported_versions = Message::Extension::SupportedVersions.new(
        msg_type: Message::HandshakeType::CLIENT_HELLO,
        versions: [Message::ProtocolVersion::TLS_1_3]
      )
      # signature_algorithms
      signature_algorithms = Message::Extension::SignatureAlgorithms.new(
        [Message::SignatureScheme::RSA_PSS_RSAE_SHA256]
      )
      # supported_groups: only P-256
      supported_groups = Message::Extension::SupportedGroups.new(
        [Message::Extension::NamedGroup::SECP256R1]
      )
      # key_share: only P-256
      ec = OpenSSL::PKey::EC.new('prime256v1')
      ec.generate_key!
      @priv_keys[Message::Extension::NamedGroup::SECP256R1] = ec
      key_share = Message::Extension::KeyShare.new(
        msg_type: Message::HandshakeType::CLIENT_HELLO,
        key_share_entry: [
          KeyShareEntry.new(
            group: Message::Extension::NamedGroup::SECP256R1,
            key_exchange: ec.public_key.to_octet_string(:uncompressed)
          )
        ]
      )

      Message::Extensions.new([supported_versions,
                               signature_algorithms,
                               supported_groups,
                               key_share])
    end
    # rubocop: enable Metrics/MethodLength

    def send_client_hello
      exs = gen_extensions
      ch = Message::ClientHello.new(extensions: exs)
      send_messages(Message::ContentType::HANDSHAKE, [ch])
      @transcript_messages[:CLIENT_HELLO] = ch
    end

    def recv_server_hello
      sh = recv_message
      raise 'unexpected message' \
        unless sh.msg_type == Message::HandshakeType::SERVER_HELLO

      @transcript_messages[:SERVER_HELLO] = sh
    end

    def recv_encrypted_extensions
      sp = recv_record
      raise 'unexpected ContentType' \
        unless sp.type == Message::ContentType::APPLICATION_DATA

      hash_len = CipherSuite.hash_len(@cipher_suite)
      messages = deserialize_server_parameters(sp.messages.first.fragment,
                                               hash_len)
      @message_queue += messages[1..]
      @transcript_messages[:ENCRYPTED_EXTENSIONS] = messages.first
    end

    def recv_certificate
      ct = recv_message
      raise 'unexpected message' \
        unless ct.msg_type == Message::HandshakeType::CERTIFICATE

      @transcript_messages[:SERVER_CERTIFICATE] = ct
    end

    def recv_certificate_verify
      cv = recv_message
      raise 'unexpected message' \
        unless cv.msg_type == Message::HandshakeType::CERTIFICATE_VERIFY

      @transcript_messages[:SERVER_CERTIFICATE_VERIFY] = cv
    end

    def recv_finished
      sf = recv_message
      raise 'unexpected message' \
        unless sf.msg_type == Message::HandshakeType::FINISHED

      @transcript_messages[:SERVER_FINISHED] = sf
    end

    def send_finished
      cf = Message::Finished.new(sign_finished)
      send_messages(Message::ContentType::HANDSHAKE, [cf])
      @transcript_messages[:CLIENT_FINISHED] = cf
    end

    # @return [Boolean]
    def verify_certificate_verify
      ct = @transcript_messages[:SERVER_CERTIFICATE]
      certificate_pem = ct.certificate_list.first.cert_data.to_pem
      cv = @transcript_messages[:SERVER_CERTIFICATE_VERIFY]
      signature_scheme = cv.signature_scheme
      signature = cv.signature
      context = 'TLS 1.3, server CertificateVerify'
      do_verify_certificate_verify(certificate_pem: certificate_pem,
                                   signature_scheme: signature_scheme,
                                   signature: signature,
                                   context: context,
                                   message_syms: CH_CT)
    end

    # @return [String]
    def sign_finished
      ch_sh = concat_messages(CH_SH)
      finished_key = @key_schedule.client_finished_key(ch_sh)
      do_sign_finished(signature_scheme: @signature_scheme,
                       finished_key: finished_key,
                       message_syms: CH_SF)
    end

    # @return [Boolean]
    def verify_finished
      ch_sh = concat_messages(CH_SH)
      finished_key = @key_schedule.server_finished_key(ch_sh)
      signature = @transcript_messages[:SERVER_FINISHED].verify_data
      do_verify_finished(signature_scheme: @signature_scheme,
                         finished_key: finished_key,
                         message_syms: CH_CV,
                         signature: signature)
    end
  end
  # rubocop: enable Metrics/ClassLength
end
