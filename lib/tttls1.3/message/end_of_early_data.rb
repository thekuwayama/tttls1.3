# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  using Refinements
  module Message
    class EndOfEarlyData
      attr_reader :msg_type

      def initialize
        @msg_type = HandshakeType::END_OF_EARLY_DATA
      end

      # @return [String]
      def serialize
        @msg_type + ''.prefix_uint24_length
      end

      # @param binary [String]
      #
      # @raise [TTTLS13::Error::ErrorAlerts]
      #
      # @return [TTTLS13::Message::EndOfEarlyData]
      def self.deserialize(binary)
        raise Error::ErrorAlerts, :internal_error if binary.nil?
        raise Error::ErrorAlerts, :decode_error unless binary.length == 4
        raise Error::ErrorAlerts, :unexpected_message \
          unless binary[0] == HandshakeType::END_OF_EARLY_DATA
        raise Error::ErrorAlerts, :decode_error \
          unless binary == "\x05\x00\x00\x00"

        EndOfEarlyData.new
      end
    end
  end
end
