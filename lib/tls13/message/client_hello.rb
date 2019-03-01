# encoding: ascii-8bit
# frozen_string_literal: true

require 'openssl'

module TLS13
  module Message
    class ClientHello
      attr_reader   :msg_type
      attr_accessor :legacy_version
      attr_accessor :random
      attr_accessor :legacy_session_id
      attr_accessor :cipher_suites
      attr_reader   :legacy_compression_methods
      attr_accessor :extensions

      # @param legacy_version [String]
      # @param random [String]
      # @param legacy_session_id [String]
      # @param cipher_suites [TLS13::Message::CipherSuites]
      # @param extensions [TLS13::Message::Extensions]
      def initialize(legacy_version: ProtocolVersion::TLS_1_2,
                     random: OpenSSL::Random.random_bytes(32),
                     legacy_session_id: Array.new(32, 0).map(&:chr).join,
                     cipher_suites: CipherSuites.new,
                     extensions: Extensions.new)
        @msg_type = HandshakeType::CLIENT_HELLO
        @legacy_version = legacy_version
        @random = random
        @legacy_session_id = legacy_session_id
        @cipher_suites = cipher_suites || CipherSuites.new
        @legacy_compression_methods = 0
        @extensions = extensions || Extensions.new
      end

      # @return [Integer]
      def length
        41 + @legacy_session_id.length + @cipher_suites.length \
        + @extensions.length
      end

      # @return [String]
      def serialize
        binary = ''
        binary += @msg_type
        binary += i2uint24(length)
        binary += @legacy_version
        binary += @random
        binary += i2uint8(@legacy_session_id.length)
        binary += @legacy_session_id
        binary += @cipher_suites.serialize
        binary += i2uint8(1) # compression methods length
        binary += i2uint8(@legacy_compression_methods)
        binary += @extensions.serialize
        binary
      end

      # @param binary [String]
      #
      # @raise [RuntimeError]
      #
      # @return [TLS13::Message::ClientHello]
      # rubocop: disable Metrics/AbcSize, Metrics/MethodLength
      def self.deserialize(binary)
        raise 'invalid HandshakeType' \
          unless binary[0] == HandshakeType::CLIENT_HELLO

        length = bin2i(binary.slice(1, 3))
        legacy_version = binary.slice(4, 2)
        random = binary.slice(6, 32)
        lsid_len = bin2i(binary[38])
        legacy_session_id = binary.slice(39, lsid_len)
        itr = 39 + lsid_len
        cs_len = bin2i(binary.slice(itr, 2))
        itr += 2
        serialized_cipher_suites = binary.slice(itr, cs_len)
        cipher_suites = CipherSuites.deserialize(serialized_cipher_suites)
        itr += cs_len
        raise 'legacy_compression_methods is not 0' unless \
          binary.slice(itr, 2) == "\x01\x00"

        itr += 2
        exs_len = bin2i(binary.slice(itr, 2))
        itr += 2
        serialized_extensions = binary.slice(itr, exs_len)
        extensions = Extensions.deserialize(serialized_extensions,
                                            HandshakeType::CLIENT_HELLO)
        itr += exs_len
        raise 'malformed binary' unless itr == length + 4

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
