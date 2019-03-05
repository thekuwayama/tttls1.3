# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  module Message
    class Finished
      attr_reader   :msg_type
      attr_accessor :verify_data

      # @param verify_data [String]
      def initialize(verify_data)
        @msg_type = HandshakeType::FINISHED
        @verify_data = verify_data
      end

      # @return [Integer]
      def length
        @verify_data.length
      end

      def hash_length
        length
      end

      # @return [String]
      def serialize
        binary = ''
        binary += @msg_type
        binary += i2uint24(length)
        binary += @verify_data
        binary
      end

      # @param binary [String]
      # @param hash_length [Integer]
      #
      # @raise [RuntimeError]
      #
      # @return [TLS13::Message::Finished]
      def self.deserialize(binary, hash_length)
        raise 'invalid HandshakeType' \
          unless binary[0] == HandshakeType::FINISHED

        msg_len = bin2i(binary.slice(1, 3))
        raise 'malformed binary' \
          unless hash_length == binary.length - 4 &&
                 msg_len == hash_length

        verify_data = binary.slice(4, hash_length)
        Finished.new(verify_data)
      end
    end
  end
end
