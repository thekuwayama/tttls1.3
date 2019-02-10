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
      # @param cipher_suites [Array of TLS13::Message::CipherSuites]
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
        # + @extensions.map(&:serialize).flatten.length
      end

      def serialize
        binary = []
        binary << @msg_type
        binary += [@length / (1 << 16), @length / (1 << 8), @length % (1 << 8)]
        binary += @legacy_version
        binary += @random
        binary << @legacy_session_id.length
        binary += @legacy_session_id
        # TODO
        # serialized_cipher_suites = @cipher_suites.serialize
        # l = serialized_cipher_suites.length
        # binary += [l / (1 << 8), l % (1 << 8)]
        # binary += serialized_cipher_suites
        binary << 1 # compression methods length
        binary << @legacy_compression_methods
        # TODO
        # serialized_extensions = @extensions.map(&:serialize).flatten
        # l = serialized_extensions.length
        # binary += [l / (1 << 8), l % (1 << 8)]
        # binary += serialized_extensions
        binary
      end

      # @param binary [Array of Integer]
      def self.deserialize(binary)
        check = binary[0] == HandshakeType::CLIENT_HELLO
        raise 'HandshakeType is not ClientHello' unless check

        # TODO
        # length = (binary[1] << 16) + (binary[2] << 8) + binary[3]
        legacy_version = [binary[4], binary[5]]
        random = binary.slice(6, 32)
        l = binary[38]
        legacy_session_id = binary.slice(39, l)
        itr = 39 + l
        l = (binary[itr] << 8) + binary[itr + 1]
        # TODO
        # serialized_cipher_suites = binary.slice(itr + 2, l)
        # cipher_suites = deserialize_cipher_suites(serialized_cipher_suites)
        itr += l + 2
        l = binary[itr]
        legacy_compression_methods = binary.slice(itr + 1, l)
        # TODO
        # itr += l + 1
        # l = (binary[itr] << 8) + binary[itr + 1]
        # serialized_extensions = binary.slice(itr + 2, l)
        # extensions = deserialize_extensions(serialized_extensions)
        ClientHello.new(legacy_version: legacy_version,
                        random: random,
                        legacy_session_id: legacy_session_id,
                        # cipher_suites: cipher_suites,
                        legacy_compression_methods: legacy_compression_methods)
        # extensions: extensions)
      end
    end
  end
end
