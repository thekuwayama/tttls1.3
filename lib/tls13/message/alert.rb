# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  module Message
    module AlertLevel
      WARNING = "\x01"
      FATAL   = "\x02"
    end

    # rubocop: disable Layout/AlignHash
    ALERT_DESCRIPTION = {
      close_notify:                    "\x00",
      unexpected_message:              "\x0a",
      bad_record_mac:                  "\x14",
      record_overflow:                 "\x16",
      handshake_failure:               "\x28",
      bad_certificate:                 "\x2a",
      unsupported_certificate:         "\x2b",
      certificate_revoked:             "\x2c",
      certificate_expired:             "\x2d",
      certificate_unknown:             "\x2e",
      illegal_parameter:               "\x2f",
      unknown_ca:                      "\x30",
      access_denied:                   "\x31",
      decode_error:                    "\x32",
      decrypt_error:                   "\x33",
      protocol_version:                "\x46",
      insufficient_security:           "\x47",
      internal_error:                  "\x50",
      inappropriate_fallback:          "\x56",
      user_canceled:                   "\x5a",
      missing_extension:               "\x6d",
      unsupported_extension:           "\x6e",
      unrecognized_name:               "\x70",
      bad_certificate_status_response: "\x71",
      unknown_psk_identity:            "\x73",
      certificate_required:            "\x74",
      no_application_protocol:         "\x78"
    }.freeze
    # rubocop: enable Layout/AlignHash

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

      def to_error
        desc = ALERT_DESCRIPTION.invert[@description]
        StandardError.new(desc)
      end
    end
  end
end
