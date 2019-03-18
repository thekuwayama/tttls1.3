# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  class Connection
    def initialize(socket)
      @socket = socket
      @key_schedule = nil
      @priv_keys = {} # Hash of NamedGroup => OpenSSL::PKey::$Object
      @read_cryptographer = Cryptograph::Passer.new
      @write_cryptographer = Cryptograph::Passer.new
      @transcript_messages = {}
      @binary_buffer = ''
      @message_queue = [] # Array of TLS13::Message::$Object
      @cipher_suite = nil # TLS13::CipherSuite
    end

    # @param type [Message::ContentType]
    # @param messages [Array of TLS13::Message::$Object]
    def send_messages(type, messages)
      record = Message::Record.new(type: type, messages: messages,
                                   cryptographer: @write_cryptographer)
      send_record(record)
    end

    # @param record [TLS13::Message::Record]
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
      buffer = @binary_buffer
      @binary_buffer = ''
      loop do
        buffer += @socket.read
        next if buffer.length < 5

        record_len = bin2i(buffer.slice(3, 2))
        next if buffer.length < record_len + 5

        @binary_buffer += buffer[record_len + 5..]
        return Record.deserialize(buffer.slice(0, record_len + 5),
                                  @read_cryptographer)
      end
    end

    CH_CT = [:CLIENT_HELLO, :SERVER_HELLO, :ENCRYPTED_EXTENSIONS,
             :CERTIFICATE].freeze

    # @return [Boolean]
    def verify_certificate_verify
      ct = @transcript_messages[:CERTIFICATE]
      certificate_pem = ct.certificate_list.first.cert_data.to_pem
      cv = @transcript_messages[:CERTIFICATE_VERIFY]
      signature_scheme = cv.signature_scheme
      signature = cv.signature
      messages = CH_CT.map { |t| @transcript_messages[t].serialize }.join
      context = 'TLS 1.3, server CertificateVerify'
      case signature_scheme
      when SignatureScheme::RSA_PSS_RSAE_SHA256
        content = "\x20" * 64 + context + "\x00" \
                  + OpenSSL::Digest::SHA256.digest(messages) # TODO: HRR
        public_key = OpenSSL::X509::Certificate.new(certificate_pem).public_key
        public_key.verify_pss('SHA256', signature, content, salt_length: :auto,
                                                            mgf1_hash: 'SHA256')
      else # TODO: other SignatureScheme
        raise 'unexpected SignatureScheme'
      end
    end

    CH_SF = [:CLIENT_HELLO, :SERVER_HELLO, :ENCRYPTED_EXTENSIONS,
             :CERTIFICATE, :CERTIFICATE_VERIFY, :SERVER_FINISHED].freeze

    # @return [String]
    def sign_finished(signature_scheme:, finished_key:)
      messages = CH_SF.map { |t| @transcript_messages[t].serialize }.join
      case signature_scheme
      when SignatureScheme::RSA_PSS_RSAE_SHA256
        hash = OpenSSL::Digest::SHA256.digest(messages) # TODO: HRR
        OpenSSL::HMAC.digest('SHA256', finished_key, hash)
      else # TODO: other SignatureScheme
        raise 'unexpected SignatureScheme'
      end
    end
  end
end
