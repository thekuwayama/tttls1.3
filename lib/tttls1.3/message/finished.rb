# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  using Refinements
  module Message
    class Finished
      attr_reader :msg_type, :verify_data

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
      # @raise [TTTLS13::Error::ErrorAlerts]
      #
      # @return [TTTLS13::Message::Finished]
      def self.deserialize(binary)
        raise Error::ErrorAlerts, :internal_error if binary.nil?
        raise Error::ErrorAlerts, :decode_error if binary.length < 4
        raise Error::ErrorAlerts, :internal_error \
          unless binary[0] == HandshakeType::FINISHED

        msg_len = Convert.bin2i(binary.slice(1, 3))
        verify_data = binary.slice(4, msg_len)
        raise Error::ErrorAlerts, :decode_error \
          unless msg_len + 4 == binary.length

        Finished.new(verify_data)
      end
    end
  end
end
