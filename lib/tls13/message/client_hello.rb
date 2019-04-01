# encoding: ascii-8bit
# frozen_string_literal: true

require 'openssl'

module TLS13
  using Refinements
  module Message
    class ClientHello
      attr_reader :msg_type
      attr_reader :legacy_version
      attr_reader :random
      attr_reader :legacy_session_id
      attr_reader :cipher_suites
      attr_reader :legacy_compression_methods
      attr_reader :extensions

      # @param legacy_version [String]
      # @param random [String]
      # @param legacy_session_id [String]
      # @param cipher_suites [TLS13::CipherSuites]
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
        @legacy_compression_methods = "\x00"
        @extensions = extensions || Extensions.new
      end

      # @return [String]
      def serialize
        binary = ''
        binary += @legacy_version
        binary += @random
        binary += @legacy_session_id.prefix_uint8_length
        binary += @cipher_suites.serialize
        binary += @legacy_compression_methods.prefix_uint8_length
        binary += @extensions.serialize

        @msg_type + binary.prefix_uint24_length
      end

      # @param binary [String]
      #
      # @raise [RuntimeError]
      #
      # @return [TLS13::Message::ClientHello]
      # rubocop: disable Metrics/AbcSize
      def self.deserialize(binary)
        raise 'invalid HandshakeType' \
          unless binary[0] == HandshakeType::CLIENT_HELLO

        msg_len = Convert.bin2i(binary.slice(1, 3))
        legacy_version = binary.slice(4, 2)
        random = binary.slice(6, 32)
        lsid_len = Convert.bin2i(binary[38])
        legacy_session_id = binary.slice(39, lsid_len)
        itr = 39 + lsid_len
        cs_len = Convert.bin2i(binary.slice(itr, 2))
        itr += 2
        cs_bin = binary.slice(itr, cs_len)
        cipher_suites = CipherSuites.deserialize(cs_bin)
        itr += cs_len
        raise 'legacy_compression_methods is not 0' unless \
          binary.slice(itr, 2) == "\x01\x00"

        itr += 2
        exs_len = Convert.bin2i(binary.slice(itr, 2))
        itr += 2
        exs_bin = binary.slice(itr, exs_len)
        extensions = Extensions.deserialize(exs_bin,
                                            HandshakeType::CLIENT_HELLO)
        itr += exs_len
        raise 'malformed binary' unless itr == msg_len + 4 &&
                                        itr == binary.length

        ClientHello.new(legacy_version: legacy_version,
                        random: random,
                        legacy_session_id: legacy_session_id,
                        cipher_suites: cipher_suites,
                        extensions: extensions)
      end
      # rubocop: enable Metrics/AbcSize
    end
  end
end
