# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  module Message
    class EncryptedExtensions
      attr_reader   :msg_type
      attr_accessor :extensions

      # @param extensions [TLS13::Message::Extensions]
      def initialize(extensions)
        @msg_type = HandshakeType::ENCRYPTED_EXTENSIONS
        @extensions = extensions || Extensions.new
      end

      # @return [Integer]
      def length
        2 + @extensions.length
      end

      # @return [String]
      def serialize
        binary = ''
        binary += @msg_type
        binary += i2uint24(length)
        binary += @extensions.serialize
        binary
      end

      # @param binary [String]
      #
      # @raise [RuntimeError]
      #
      # @return [TLS13::Message::EncryptedExtensions]
      def self.deserialize(binary)
        raise 'invalid msg_type' \
          unless binary[0] == HandshakeType::ENCRYPTED_EXTENSIONS

        ee_len = bin2i(binary.slice(1, 3))
        exs_len = bin2i(binary.slice(4, 2))
        raise 'malformed binary' unless ee_len == exs_len + 2

        extensions = Extensions.deserialize(binary.slice(6, exs_len),
                                            HandshakeType::ENCRYPTED_EXTENSIONS)
        EncryptedExtensions.new(extensions)
      end
    end
  end
end
