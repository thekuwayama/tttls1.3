module TLS13
  module Message
    class ClientHello
      attr_accessor :msg_type
      attr_accessor :length
      attr_accessor :legacy_version
      attr_accessor :random
      attr_accessor :legacy_session_id
      attr_accessor :cipher_suites
      attr_accessor :legacy_compression_methods
      attr_accessor :extensions

      # @param legacy_version [Array of Integer]
      # @param random [Array of Integer]
      # @param legacy_session_id [Array of Integer]
      # @param cipher_suites [TLS13::Message::CipherSuite]
      # @param legacy_compression_methods [Integer]
      # @param extensions [Array of TLS13::Message::Extension]
      def initialize(**settings)
        # TODO
      end

      def serialize
        # TODO
      end

      # @param binary [Array of Integer]
      def self.deserialize(binary)
        # TODO
      end
    end
  end
end
