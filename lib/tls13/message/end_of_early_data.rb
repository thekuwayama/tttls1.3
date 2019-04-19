# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  module Message
    class EndOfEarlyData
      # @return [String]
      def serialize
        ''
      end

      # @param binary [String]
      #
      # @raise [TLS13::Error::ErrorAlerts]
      #
      # @return [TLS13::Message::EndOfEarlyData]
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
