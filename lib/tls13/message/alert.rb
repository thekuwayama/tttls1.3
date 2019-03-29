# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  module Message
    module AlertLevel
      WARNING = "\x01"
      FATAL   = "\x02"
    end

    module AlertDescription
      CLOSE_NOTIFY                    = "\x00"
      UNEXPECTED_MESSAGE              = "\x0a"
      BAD_RECORD_MAC                  = "\x14"
      RECORD_OVERFLOW                 = "\x16"
      HANDSHAKE_FAILURE               = "\x28"
      BAD_CERTIFICATE                 = "\x2a"
      UNSUPPORTED_CERTIFICATE         = "\x2b"
      CERTIFICATE_REVOKED             = "\x2c"
      CERTIFICATE_EXPIRED             = "\x2d"
      CERTIFICATE_UNKNOWN             = "\x2e"
      ILLEGAL_PARAMETER               = "\x2f"
      UNKNOWN_CA                      = "\x30"
      ACCESS_DENIED                   = "\x31"
      DECODE_ERROR                    = "\x32"
      DECRYPT_ERROR                   = "\x33"
      PROTOCOL_VERSION                = "\x46"
      INSUFFICIENT_SECURITY           = "\x47"
      INTERNAL_ERROR                  = "\x50"
      INAPPROPRIATE_FALLBACK          = "\x56"
      USER_CANCELED                   = "\x5a"
      MISSING_EXTENSION               = "\x6d"
      UNSUPPORTED_EXTENSION           = "\x6e"
      UNRECOGNIZED_NAME               = "\x70"
      BAD_CERTIFICATE_STATUS_RESPONSE = "\x71"
      UNKNOWN_PSK_IDENTITY            = "\x73"
      CERTIFICATE_REQUIRED            = "\x74"
      NO_APPLICATION_PROTOCOL         = "\x78"
    end

    class Alert
      attr_reader :level
      attr_reader :description

      # @param level [TLS13::Message::AlertLevel]
      # @param description [TLS13::Message::AlertDescription]
      def initialize(level:, description:)
        @level = level
        @description = description
      end

      # @return [String]
      def serialize
        @level + @description
      end

      # @param binary [String]
      #
      # @raise [RuntimeError]
      #
      # @return [TLS13::Message::Alert]
      def self.deserialize(binary)
        raise 'malformed binary' unless binary.length == 2

        level = binary[0]
        description = binary[1]
        Alert.new(level: level, description: description)
      end
    end
  end
end
