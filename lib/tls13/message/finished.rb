# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  using Refinements
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
      def hash_length
        @verify_data.length
      end

      # @return [String]
      def serialize
        @msg_type + @verify_data.prefix_uint24_length
      end

      alias fragment serialize

      # @param binary [String]
      #
      # @raise [RuntimeError]
      #
      # @return [TLS13::Message::Finished]
      def self.deserialize(binary)
        raise 'invalid HandshakeType' \
          unless binary[0] == HandshakeType::FINISHED

        msg_len = Convert.bin2i(binary.slice(1, 3))
        raise 'malformed binary' unless binary.length - 4 == msg_len

        verify_data = binary.slice(4, msg_len)
        Finished.new(verify_data)
      end
    end
  end
end
