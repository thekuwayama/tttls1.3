# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  module Error
    # Generic error, common for all classes under TTTLS13::Error module.
    class Error < StandardError; end

    # Raised if configure is invalid.
    class ConfigError < Error; end

    # Raised on received Error Alerts message or invalid message.
    # https://tools.ietf.org/html/rfc8446#section-6.2
    # Terminated the connection, so you *cannot* recover from this exception.
    class ErrorAlerts < Error
      # @return [TTTLS13::Message::Alert]
      def to_alert
        Message::Alert.new(description: ALERT_DESCRIPTION[message.to_sym])
      end
    end
  end
end
