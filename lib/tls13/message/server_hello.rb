# encoding: ascii-8bit
# frozen_string_literal: true

require 'openssl'

module TLS13
  module Message
    class ServerHello
      attr_reader :msg_type
      attr_reader :legacy_version
      attr_reader :random
      attr_reader :legacy_session_id_echo
      attr_reader :cipher_suite
      attr_reader :legacy_compression_method
      attr_reader :extensions

      # @param legacy_version [String]
      # @param random [String]
      # @param legacy_session_id_echo [String]
      # @param cipher_suite [TLS13::Message::CipherSuite]
      # @param extensions [TLS13::Message::Extensions]
      def initialize(legacy_version: ProtocolVersion::TLS_1_2,
                     random: OpenSSL::Random.random_bytes(32),
                     legacy_session_id_echo: nil,
                     cipher_suite:,
                     extensions: Extensions.new)
        @msg_type = HandshakeType::SERVER_HELLO
        @legacy_version = legacy_version
        @random = random
        @legacy_session_id_echo = legacy_session_id_echo
        @cipher_suite = cipher_suite || ''
        @legacy_compression_method = "\x00"
        @extensions = extensions || Extensions.new
      end

      # @return [Integer]
      def length
        40 + @legacy_session_id_echo.length + @extensions.length
      end

      # @return [String]
      def serialize
        binary = ''
        binary += @msg_type
        binary += i2uint24(length)
        binary += @legacy_version
        binary += @random
        binary += uint8_length_prefix(@legacy_session_id_echo)
        binary += @cipher_suite
        binary += @legacy_compression_method
        binary += @extensions.serialize
        binary
      end

      # @param binary [String]
      #
      # @raise [RuntimeError]
      #
      # @return [TLS13::Message::ServerHello]
      # rubocop: disable Metrics/MethodLength
      def self.deserialize(binary)
        raise 'invalid HandshakeType' \
          unless binary[0] == HandshakeType::SERVER_HELLO

        msg_len = bin2i(binary.slice(1, 3))
        legacy_version = binary.slice(4, 2)
        random = binary.slice(6, 32)
        lsid_len = bin2i(binary[38])
        legacy_session_id_echo = binary.slice(39, lsid_len)
        itr = 39 + lsid_len
        cipher_suite = binary.slice(itr, 2)
        itr += 2
        raise 'legacy_compression_method is not 0' unless \
          binary[itr] == "\x00"

        itr += 1
        exs_len = bin2i(binary.slice(itr, 2))
        itr += 2
        serialized_extensions = binary.slice(itr, exs_len)
        extensions = Extensions.deserialize(serialized_extensions,
                                            HandshakeType::SERVER_HELLO)
        itr += exs_len
        raise 'malformed binary' unless itr == msg_len + 4

        ServerHello.new(legacy_version: legacy_version,
                        random: random,
                        legacy_session_id_echo: legacy_session_id_echo,
                        cipher_suite: cipher_suite,
                        extensions: extensions)
      end
      # rubocop: enable Metrics/MethodLength
    end
  end
end
