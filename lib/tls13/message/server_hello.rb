# encoding: ascii-8bit
# frozen_string_literal: true

require 'openssl'

module TLS13
  using Refinements
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
      # @param cipher_suite [TLS13::CipherSuite]
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

      # @return [String]
      def serialize
        binary = ''
        binary += @legacy_version
        binary += @random
        binary += @legacy_session_id_echo.prefix_uint8_length
        binary += @cipher_suite
        binary += @legacy_compression_method
        binary += @extensions.serialize

        @msg_type + binary.prefix_uint24_length
      end

      # @param binary [String]
      #
      # @raise [TLS13::Error::InternalError, TLSError]
      #
      # @return [TLS13::Message::ServerHello]
      # rubocop: disable Metrics/AbcSize
      # rubocop: disable Metrics/CyclomaticComplexity
      def self.deserialize(binary)
        raise Error::InternalError if binary.nil?
        raise Error::TLSError, :decode_error if binary.length < 39
        raise Error::InternalError \
          unless binary[0] == HandshakeType::SERVER_HELLO

        msg_len = Convert.bin2i(binary.slice(1, 3))
        legacy_version = binary.slice(4, 2)
        random = binary.slice(6, 32)
        lsid_len = Convert.bin2i(binary[38])
        legacy_session_id_echo = binary.slice(39, lsid_len)
        i = 39 + lsid_len
        cipher_suite = binary.slice(i, 2)
        i += 2
        raise Error::TLSError, :illegal_parameter \
          unless binary[i] == "\x00"

        i += 1
        exs_len = Convert.bin2i(binary.slice(i, 2))
        i += 2
        exs_bin = binary.slice(i, exs_len)
        extensions = Extensions.deserialize(exs_bin,
                                            HandshakeType::SERVER_HELLO)
        i += exs_len
        raise Error::TLSError, :decode_error unless i == msg_len + 4 &&
                                                    i == binary.length

        ServerHello.new(legacy_version: legacy_version,
                        random: random,
                        legacy_session_id_echo: legacy_session_id_echo,
                        cipher_suite: cipher_suite,
                        extensions: extensions)
      end
      # rubocop: enable Metrics/AbcSize
      # rubocop: enable Metrics/CyclomaticComplexity
    end
  end
end
