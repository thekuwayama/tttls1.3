# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  module Message
    class ChangeCipherSpec
      # @return [String]
      def serialize
        "\x01"
      end

      # @param binary [String]
      #
      # @raise [RuntimeError]
      #
      # @return [TLS13::Message::ChangeCipherSpec]
      def self.deserialize(binary)
        raise 'invalid binary' unless binary[0] == "\x01"

        ChangeCipherSpec.new
      end
    end
  end
end
