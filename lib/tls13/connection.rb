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

    def send_ccs
      ccs_record = Message::Record.new(
        type: Message::ContentType::CCS,
        legacy_record_version: Message::ProtocolVersion::TLS_1_2,
        messages: [Message::ChangeCipherSpec.new],
        cryptographer: Cryptograph::Passer.new
      )
      send_record(ccs_record)
    end

    # @return [TLS13::Message::$Object]
    def recv_message
      return @message_queue.shift unless @message_queue.empty?

      loop do
        messages = []
        record = recv_record
        case record.type
        when Message::ContentType::HANDSHAKE
          messages = record.messages
        when Message::ContentType::APPLICATION_DATA
          hash_len = CipherSuite.hash_len(@cipher_suite)
          messages = Message.deserialize_server_parameters(
            record.messages.first.fragment,
            hash_len
          )
        when Message::ContentType::CCS
          next # skip
        when Message::ContentType::ALERT
          next # TODO
        else
          raise 'unexpected ContentType'
        end
        @message_queue += messages[1..]
        return messages.first
      end
    end

    # @return [TLS13::Message::Record]
    def recv_record
      buffer = @socket.read(5)
      record_len = bin2i(buffer.slice(3, 2))
      buffer += @socket.read(record_len)
      Message::Record.deserialize(buffer, @read_cryptographer)
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

    # @param digest [String] name of digest algorithm
    # @param finished_key [String]
    # @param message_range [Range]
    #
    # @return [String]
    def do_sign_finished(digest:, finished_key:, message_range:)
      messages = concat_messages(message_range)
      hash = OpenSSL::Digest.digest(digest, messages)
      OpenSSL::HMAC.digest(digest, finished_key, hash)
    end

    # @param digest [String] name of digest algorithm
    # @param finished_key [String]
    # @param message_range [Range]
    # @param signature [String]
    #
    # @return [Boolean]
    def do_verify_finished(digest:, finished_key:, message_range:, signature:)
      do_sign_finished(digest: digest,
                       finished_key: finished_key,
                       message_range: message_range) == signature
    end
  end
end
