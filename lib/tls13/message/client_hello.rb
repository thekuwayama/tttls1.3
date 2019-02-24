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

      # @param legacy_version [String]
      # @param random [String]
      # @param legacy_session_id [String]
      # @param cipher_suites [TLS13::Message::CipherSuites]
      # @param extensions [Array of Extension]
      def initialize(legacy_version: ProtocolVersion::TLS_1_2,
                     random: OpenSSL::Random.random_bytes(32),
                     legacy_session_id: Array.new(32, 0).map(&:chr).join,
                     cipher_suites: DEFALT_CIPHER_SUITES,
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
                  + 2 + @legacy_session_id.length \
                  + 2 + @cipher_suites.serialize.length \
                  + 2 + @extensions.extensions.map { |x| x.length + 4 }
                                   .sum
      end

      # @return [String]
      def serialize
        binary = ''
        binary << @msg_type
        binary += i2uint24(@length)
        binary += @legacy_version
        binary += @random
        binary << @legacy_session_id.length
        binary += @legacy_session_id
        binary += @cipher_suites.serialize
        binary << 1 # compression methods length
        binary << @legacy_compression_methods
        # TODO
        # serialized_extensions = @extensions.map(&:serialize).flatten
        # exs_len = serialized_extensions.length
        # binary += i2uint16(exs_len)
        # binary += serialized_extensions
        binary
      end

      # @param binary [String]
      #
      # @raise [RuntimeError]
      #
      # @return [TLS13::Message::ClientHello]
      # rubocop: disable Metrics/AbcSize, Metrics/MethodLength
      def self.deserialize(binary)
        check = binary[0] == HandshakeType::CLIENT_HELLO
        raise 'msg_type is invalid' unless check

        # TODO: check length
        # length = bin2i(binary.slice(1, 3))
        legacy_version = binary.slice(4, 2)
        random = binary.slice(6, 32)
        lsid_len = bin2i(binary[38])
        legacy_session_id = binary.slice(39, lsid_len)
        itr = 39 + lsid_len
        cs_len = bin2i(binary.slice(itr, 2))
        serialized_cipher_suites = binary.slice(itr, cs_len + 2)
        cipher_suites = CipherSuites.deserialize(serialized_cipher_suites)
        itr += cs_len + 2
        raise 'legacy_compression_methods is not 0' unless \
          binary.slice(itr, 2) == "\x01\x00"

        itr += 2
        exs_len = bin2i(binary.slice(itr, 2))
        serialized_extensions = binary.slice(itr, exs_len + 2)
        extensions = Extensions.deserialize(serialized_extensions,
                                            HandshakeType::CLIENT_HELLO)
        ClientHello.new(legacy_version: legacy_version,
                        random: random,
                        legacy_session_id: legacy_session_id,
                        cipher_suites: cipher_suites,
                        extensions: extensions)
      end
      # rubocop: enable Metrics/AbcSize, Metrics/MethodLength
    end
  end
end
