# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  module Message
    class ChangeCipherSpec
      # @return [String]
      def serialize
        "\x01"
      end

      # @param binary [String]
      #
      # @raise [TTTLS13::Error::ErrorAlerts]
      #
      # @return [TTTLS13::Message::ChangeCipherSpec]
      def self.deserialize(binary)
        raise Error::ErrorAlerts, :internal_error if binary.nil?
        raise Error::ErrorAlerts, :decode_error unless binary.length == 1
        raise Error::ErrorAlerts, :unexpected_message unless binary[0] == "\x01"

        ChangeCipherSpec.new
      end
    end
  end
end
