require 'openssl'

module TLS13
  module Message
    class ClientHello
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
        default_settings = {
          legacy_version: ProtocolVersion::TLS_1_2,
          legacy_compression_methods: 0
        }
        settings = default_settings.merge(settings)
        @legacy_version = settings[:legacy_version]
        @randome = settings[:randome] \
                   || OpenSSL::Random.random_bytes(32).unpack('C*')
        @legacy_session_id = settings[:legacy_session_id] || Array.new(32, 0)
        @cipher_suites = settings[:cipher_suites]
        @legacy_compression_methods = settings[:legacy_compression_methods]
        @extensions = settings[:extensions]
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
