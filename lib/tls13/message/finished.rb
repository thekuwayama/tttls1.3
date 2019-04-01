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

      # @return [String]
      def serialize
        @msg_type + @verify_data.prefix_uint24_length
      end

      alias fragment serialize

      # @param binary [String]
      #
      # @raise [TLS13::Error::InternalError, TLSError]
      #
      # @return [TLS13::Message::Finished]
      def self.deserialize(binary)
        raise Error::InternalError if binary.nil?
        raise Error::TLSError, 'decode_error' if binary.length < 4
        raise Error::InternalError \
          unless binary[0] == HandshakeType::FINISHED

        msg_len = Convert.bin2i(binary.slice(1, 3))
        verify_data = binary.slice(4, msg_len)
        raise Error::TLSError, 'decode_error' \
          unless msg_len + 4 == binary.length

        Finished.new(verify_data)
      end
    end
  end
end
