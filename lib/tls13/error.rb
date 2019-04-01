# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  module Error
    # Generic error, common for all classes under TLS13::Error module.
    class Error < StandardError; end

    # Raised if configure is invalid.
    class ConfigError < Error; end

    # Raised on invalid connection processing.
    class InternalError < Error; end

    # Raised on received Alert message or invalid message.
    # Terminated the connection, so you *cannot* recover from this exception.
    class TLSError < Error
      # @return [TLS13::Message::Alert]
      def to_alert
        Message::Alert.new(description: ALERT_DESCRIPTION[message.to_sym])
      end
    end
  end
end
