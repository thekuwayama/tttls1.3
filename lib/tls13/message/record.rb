# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  module Message
    class Record
      attr_accessor :type
      attr_accessor :legacy_record_version
      attr_accessor :fragment
      attr_accessor :messages
      attr_accessor :cryptographer

      # @param type [TLS13::Message::ContentType]
      # @param legacy_record_version [TLS13::Message::ProtocolVersion]
      # @param messages [Array of TLS13::Message::$Object]
      # @param cryptographer [TLS13::Cryptograph::$Object]
      #
      # @raise [RuntimeError]
      def initialize(type: ContentType::INVALID,
                     legacy_record_version: ProtocolVersion::TLS_1_2,
                     messages: [],
                     cryptographer: nil)
        @type = type
        @legacy_record_version = legacy_record_version
        @messages = messages || []
        @cryptographer = cryptographer
      end

      # @raise [RuntimeError]
      #
      # @return [Integer]
      def length
        case @type
        when ContentType::HANDSHAKE
          @messages.map { |x| x.length + 4 }.sum
        when ContentType::CCS
          1
        else # TODO
          raise 'unexpected ContentType'
        end
      end

      # @return [String]
      def serialize
        binary = ''
        binary += @type
        binary += @legacy_record_version
        binary += i2uint16(length)
        binary += @messages.map(&:serialize).join
        binary
      end

      # @param binary [String]
      # @param cryptographer [TLS13::Cryptograph::$Object]
      #
      # @raise [RuntimeError]
      #
      # @return [TLS13::Message::Record]
      def self.deserialize(binary, cryptographer)
        raise 'too short binary' if binary.nil? || binary.length < 5

        type = binary[0]
        legacy_record_version = binary.slice(1, 2)
        length = bin2i(binary.slice(3, 2))
        fragment = binary.slice(5, length)
        plaintext = cryptographer.decrypt(fragment)
        messages = deserialize_fragment(plaintext, type)
        Record.new(type: type,
                   legacy_record_version: legacy_record_version,
                   messages: messages,
                   cryptographer: cryptographer)
      end

      # @param binary [String]
      # @param type [TLS13::Message::ContentType]
      #
      # @raise [RuntimeError]
      #
      # @return [Array of TLS13::Message::$Object]
      def self.deserialize_fragment(binary, type)
        raise 'zero-length fragments' if binary.nil? || binary.empty?

        case type
        when ContentType::HANDSHAKE
          deserialize_handshake(binary)
        when ContentType::CCS
          [ChangeCipherSpec.deserialize(binary)]
        else # TODO
          raise 'unknown ContentType'
        end
      end

      # @param binary [String]
      #
      # @raise [RuntimeError]
      #
      # @return [Array of TLS13::Message::$Object]
      def self.deserialize_handshake(binary)
        handshakes = [] # TODO: concatenated handshakes
        message = nil
        msg_type = binary[itr]
        case msg_type
        when HandshakeType::CLIENT_HELLO
          message = ClientHello.deserialize(binary)
        when HandshakeType::SERVER_HELLO
          message = ServerHello.deserialize(binary)
        when HandshakeType::ENCRYPTED_EXTENSIONS
          message = EncryptedExtensions.deserialize(binary)
        else # TODO
          raise 'unexpected HandshakeType'
        end
        handshakes << message
        handshakes
      end
    end
  end
end
