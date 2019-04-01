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
      # @raise [TLS13::Error::InternalError, TLSError]
      #
      # @return [TLS13::Message::ChangeCipherSpec]
      def self.deserialize(binary)
        raise Error::InternalError if binary.nil?
        raise Error::TLSError, 'decode_error' unless binary.length == 1
        raise Error::TLSError, 'unexpected_message' unless binary[0] == "\x01"

        ChangeCipherSpec.new
      end
    end
  end
end
