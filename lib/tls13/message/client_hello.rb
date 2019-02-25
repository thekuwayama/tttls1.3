# encoding: ascii-8bit
# frozen_string_literal: true

require 'openssl'

module TLS13
  module Message
    class ClientHello
      attr_reader   :msg_type
      attr_accessor :length
      attr_accessor :legacy_version
      attr_accessor :random
      attr_accessor :legacy_session_id
      attr_accessor :cipher_suites
      attr_accessor :legacy_compression_methods
      attr_accessor :extensions

      # @param legacy_version [String]
      # @param random [String]
      # @param legacy_session_id_echo [String]
      # @param cipher_suite [Array of CipherSuites]
      # @param extensions [Hash of Extension]
      def initialize(legacy_version: ProtocolVersion::TLS_1_2,
                     random: OpenSSL::Random.random_bytes(32),
                     legacy_session_id: Array.new(32, 0).map(&:chr).join,
                     cipher_suites: DEFALT_CIPHER_SUITES,
                     extensions: {})
        @msg_type = HandshakeType::CLIENT_HELLO
        @legacy_version = legacy_version
        @random = random
        @legacy_session_id = legacy_session_id
        @cipher_suites = cipher_suites
        @legacy_compression_methods = 0
        @extensions = extensions || {}
        @length = 34 \
                  + 1 + @legacy_session_id.length \
                  + 2 + @cipher_suites.length  \
                  + 2 \
                  + 2 + @extensions.length
      end

      # @return [String]
      def serialize
        binary = ''
        binary += @msg_type
        binary += i2uint24(@length)
        binary += @legacy_version
        binary += @random
        binary << @legacy_session_id.length
        binary += @legacy_session_id
        binary += @cipher_suites.serialize
        binary << 1 # compression methods length
        binary << @legacy_compression_methods
        serialized_extensions = @extensions.extensions.values.map(&:serialize).join
        exs_len = serialized_extensions.length
        binary += i2uint16(exs_len)
        binary += serialized_extensions
        binary
      end

      # @param binary [String]
      #
      # @raise [RuntimeError]
      #
      # @return [TLS13::Message::ClientHello]
      # rubocop: disable Metrics/MethodLength
      def self.deserialize(binary)
        raise 'msg_type is invalid' \
          unless binary[0] == HandshakeType::CLIENT_HELLO

        length = bin2i(binary.slice(1, 3))
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
        itr += exs_len + 2
        raise 'malformed binary' unless itr == length + 4

        ClientHello.new(legacy_version: legacy_version,
                        random: random,
                        legacy_session_id: legacy_session_id,
                        cipher_suites: cipher_suites,
                        extensions: extensions)
      end
      # rubocop: enable Metrics/MethodLength
    end
  end
end
