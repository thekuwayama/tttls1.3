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
          recv_server_hello
          # get key, nonce using key_schedule
          # @key_schedule
          @cipher_suite = sh.cipher_suite
          @cryptographer = Cryptograph::Aead.new(
            cipher_suite: @cipher_suite,
            key: nil, # TODO
            nonce: nil, # TODO
            type: ContentType::HANDSHAKE
          )
          state = ClientState::WAIT_EE
        when ClientState::WAIT_EE
          next # TODO
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
      ch = Message::ClientHello.new # TODO: set ClientHello
      send_messages(Message::ContentType::HANDSHAKE, [ch])
      @transcript_messages[HandshakeType::CLIENT_HELLO] = ch
    end

    def recv_server_hello
      sh = recv_message
      raise 'unexpected message' \
        unless sh.msg_type == Message::HandshakeType::SERVER_HELLO

      # TODO: check ServerHello
      @transcript_messages[HandshakeType::SERVER_HELLO] = sh
    end
  end
end
