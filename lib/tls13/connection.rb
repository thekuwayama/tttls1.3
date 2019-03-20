# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  CH1  = 0
  HRR  = 1
  CH   = 2
  SH   = 3
  EE   = 4
  CR   = 5
  CT   = 6
  CV   = 7
  SF   = 8
  EOED = 9
  CCT  = 10
  CCV  = 11
  CF   = 12

  class Connection
    def initialize(socket)
      @socket = socket
      @key_schedule = nil
      @priv_keys = {} # Hash of NamedGroup => OpenSSL::PKey::$Object
      @read_cryptographer = Cryptograph::Passer.new
      @write_cryptographer = Cryptograph::Passer.new
      @transcript = {}
      @binary_buffer = ''
      @message_queue = [] # Array of TLS13::Message::$Object
      @cipher_suite = nil # TLS13::CipherSuite
      @signature_scheme = nil # TLS13::Message::SignatureScheme
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
        return Message::Record.deserialize(buffer.slice(0, record_len + 5),
                                           @read_cryptographer)
      end
    end

    # @param range [Range]
    #
    # @return [String]
    def concat_messages(range)
      # TODO: HRR
      range.to_a.map do |m|
        @transcript.key?(m) ? @transcript[m].serialize : ''
      end.join
    end

    # @param certificate_pem [String]
    # @param signature_scheme [TLS13::Message::SignatureScheme]
    # @param signature [String]
    # @param context [String]
    # @param message_range [Range]
    #
    # @raise [RuntimeError]
    #
    # @return [Boolean]
    def do_verify_certificate_verify(certificate_pem:, signature_scheme:,
                                     signature:, context:, message_range:)
      messages = concat_messages(message_range)
      case signature_scheme
      when Message::SignatureScheme::RSA_PSS_RSAE_SHA256
        hash = OpenSSL::Digest::SHA256.digest(messages)
        content = "\x20" * 64 + context + "\x00" + hash
        public_key = OpenSSL::X509::Certificate.new(certificate_pem).public_key
        public_key.verify_pss('SHA256', signature, content, salt_length: :auto,
                                                            mgf1_hash: 'SHA256')
      else # TODO: other SignatureScheme
        raise 'unexpected SignatureScheme'
      end
    end

    # @param signature_scheme [TLS13::Message::SignatureScheme]
    # @param finished_key [String]
    # @param message_range [Range]
    #
    # @raise [RuntimeError]
    #
    # @return [String]
    def do_sign_finished(signature_scheme:, finished_key:, message_range:)
      messages = concat_messages(message_range)
      case signature_scheme
      when Message::SignatureScheme::RSA_PSS_RSAE_SHA256
        hash = OpenSSL::Digest::SHA256.digest(messages)
        OpenSSL::HMAC.digest('SHA256', finished_key, hash)
      else # TODO: other SignatureScheme
        raise 'unexpected SignatureScheme'
      end
    end

    # @param signature_scheme [TLS13::Message::SignatureScheme]
    # @param finished_key [String]
    # @param message_range [Range]
    # @param signature [String]
    #
    # @return [Boolean]
    def do_verify_finished(signature_scheme:, finished_key:, message_range:,
                           signature:)
      do_sign_finished(signature_scheme: signature_scheme,
                       finished_key: finished_key,
                       message_range: message_range) == signature
    end
  end
end
