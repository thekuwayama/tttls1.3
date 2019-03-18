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

  class Client < Connection
    # rubocop: disable Metrics/MethodLength
    # rubocop: disable Metrics/BlockLength
    # rubocop: disable Metrics/CyclomaticComplexity
    def connect
      state = ClientState::START
      loop do
        case state
        when ClientState::START
          send_client_hello
          state = ClientState::WAIT_SH
        when ClientState::WAIT_SH
          sh = recv_server_hello
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
          state = ClientState::WAIT_EE
        when ClientState::WAIT_EE
          recv_encrypted_extensions
          # TODO: get server parameters
        when ClientState::WAIT_CERT_CR
          next # TODO
        when ClientState::WAIT_CERT
          next # TODO
        when ClientState::WAIT_CV
          next # TODO
        when ClientState::WAIT_FINISHED
          next # TODO
        when ClientState::CONNECTED
          break
        end
      end
    end
    # rubocop: enable Metrics/MethodLength
    # rubocop: enable Metrics/BlockLength
    # rubocop: enable Metrics/CyclomaticComplexity

    def send_client_hello
      # only P-256
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
      # TODO: set Extensions using config
      exs = Message::Extensions.new([key_share])
      ch = Message::ClientHello.new(extensions: exs)
      send_messages(Message::ContentType::HANDSHAKE, [ch])
      @transcript_messages[:CLIENT_HELLO] = ch
    end

    def recv_server_hello
      sh = recv_message
      raise 'unexpected message' \
        unless sh.msg_type == Message::HandshakeType::SERVER_HELLO

      # TODO: check ServerHello
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
      # TODO: check EncryptedExtensions
      @transcript_messages[:ENCRYPTED_EXTENSIONS] = messages.first
    end
  end
end
