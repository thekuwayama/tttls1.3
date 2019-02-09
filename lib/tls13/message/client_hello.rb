require 'openssl'

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
      # @param extensions [Array of TLS13::Message::Extension]
      def initialize(legacy_version: ProtocolVersion::TLS_1_2,
                     random: OpenSSL::Random.random_bytes(32).unpack('C*'),
                     legacy_session_id: Array.new(32, 0),
                     cipher_suites: [],
                     extensions: [])
        @msg_type = HandshakeType::CLIENT_HELLO
        @legacy_version = legacy_version
        @random = random
        @legacy_session_id = legacy_session_id
        @cipher_suites = cipher_suites
        @legacy_compression_methods = 0
        @extensions = extensions
        @length = @legacy_version.length \
                  + @random.length \
                  + @legacy_session_id.length \
                  + 2
        # TODO
        # + @cipher_suites.serialize.length \
        # TODO
        # @extensions.map(&:serialize).flatten.length
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
