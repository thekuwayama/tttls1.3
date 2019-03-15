# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  class Connection
    def initialize(socket)
      @socket = socket
      # TODO
      # @state
      @buffer = ''
      @binary_buffer = ''
      @message_queue = [] # Array of TLS13::Message::$Object
    end

    # @params type [Message::ContentType]
    # @params messages [Array of TLS13::Message::$Object]
    def send_messages(type, messages)
      record = Message::Record(type: type, messages: messages,
                               cryptographer: Cryptgraph::Passer.new)
      # cryptographer: @state.cryptgrapher)
      send_record(record)
    end

    # @params record [TLS13::Message::Record]
    def send_record(record)
      @socket.write(record.serialize)
    end

    # @return [TLS13::Message::$Object]
    def recv_message
      return @message_queue.shift unless @message_queue.empty?

      messages = recv_record.messages
      @message_queue += messages[1..]
      messages.first
    end

    # @return [TLS13::Message::Record]
    def recv_record
      buffer = @binary_buffer.shift(@binary_buffer.length)
      loop do
        buffer += @socket.read
        next if buffer.length < 5

        record_len = bin2i(buffer.slice(3, 2))
        next if buffer.length < record_len

        @binary_buffer += buffer[record_len..]
        return Record.deserialize(buffer.slice(0, record_len),
                                  Cryptgraph::Passer.new)
        # return Record.deserialize(buffer.slice(0, record_len),
        #                           @state.cryptgrapher)
      end
    end

    def verify_certificate_verify(signature_scheme:, certificate_pem:,
                                  signature:, transcript:)
      context = 'TLS 1.3, server CertificateVerify'
      case signature_scheme
      when SignatureScheme::RSA_PSS_RSAE_SHA256
        content = "\x20" * 64 + context + "\x00" \
                  + OpenSSL::Digest::SHA256.digest(transcript) # TODO: HRR
        public_key = OpenSSL::X509::Certificate.new(certificate_pem).public_key
        public_key.verify_pss('SHA256', signature, content, salt_length: :auto,
                                                            mgf1_hash: 'SHA256')
      else # TODO
        raise 'unexpected SignatureScheme'
      end
    end

    def sign_finished(signature_scheme:, finished_key:, transcript:)
      case signature_scheme
      when SignatureScheme::RSA_PSS_RSAE_SHA256
        hash = OpenSSL::Digest::SHA256.digest(transcript) # TODO: HRR
        OpenSSL::HMAC.digest('SHA256', finished_key, hash)
      else # TODO
        raise 'unexpected SignatureScheme'
      end
    end
  end
end
