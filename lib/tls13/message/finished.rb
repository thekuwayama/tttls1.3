# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  module Message
    class Finished
      attr_reader :msg_type
      attr_reader :verify_data

      # @param verify_data [String]
      def initialize(verify_data)
        @msg_type = HandshakeType::FINISHED
        @verify_data = verify_data
      end

      # @return [Integer]
      def length
        @verify_data.length
      end

      alias hash_length length

      # @return [String]
      def serialize
        binary = ''
        binary += @msg_type
        binary += i2uint24(length)
        binary += @verify_data
        binary
      end

      alias fragment serialize

      # @param binary [String]
      # @param hash_len [Integer]
      #
      # @raise [RuntimeError]
      #
      # @return [TLS13::Message::Finished]
      def self.deserialize(binary, hash_len)
        raise 'invalid HandshakeType' \
          unless binary[0] == HandshakeType::FINISHED

        msg_len = bin2i(binary.slice(1, 3))
        raise 'malformed binary' \
          unless hash_len == binary.length - 4 &&
                 msg_len == hash_len

        verify_data = binary.slice(4, hash_len)
        Finished.new(verify_data)
      end
    end
  end
end
