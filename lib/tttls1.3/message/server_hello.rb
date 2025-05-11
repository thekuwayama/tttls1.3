# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  using Refinements
  module Message
    # https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-1
    APPEARABLE_SH_EXTENSIONS = [
      ExtensionType::PRE_SHARED_KEY,
      ExtensionType::PASSWORD_SALT,
      ExtensionType::SUPPORTED_VERSIONS,
      ExtensionType::KEY_SHARE
    ].freeze
    private_constant :APPEARABLE_SH_EXTENSIONS

    APPEARABLE_HRR_EXTENSIONS = [
      ExtensionType::COOKIE,
      ExtensionType::PASSWORD_SALT,
      ExtensionType::SUPPORTED_VERSIONS,
      ExtensionType::KEY_SHARE,
      ExtensionType::ENCRYPTED_CLIENT_HELLO
    ].freeze
    private_constant :APPEARABLE_HRR_EXTENSIONS

    DOWNGRADE_PROTECTION_TLS_1_2 = "\x44\x4F\x57\x4E\x47\x52\x44\x01"
    private_constant :DOWNGRADE_PROTECTION_TLS_1_2

    DOWNGRADE_PROTECTION_TLS_1_1 = "\x44\x4F\x57\x4E\x47\x52\x44\x00"
    private_constant :DOWNGRADE_PROTECTION_TLS_1_1

    # special value of the SHA-256 of "HelloRetryRequest"
    HRR_RANDOM \
    = "\xcf\x21\xad\x74\xe5\x9a\x61\x11\xbe\x1d\x8c\x02\x1e\x65\xb8\x91" \
      "\xc2\xa2\x11\x16\x7a\xbb\x8c\x5e\x07\x9e\x09\xe2\xc8\xa8\x33\x9c"

    class ServerHello
      attr_reader :msg_type, :legacy_version, :random, :legacy_session_id_echo, :cipher_suite,
                  :legacy_compression_method, :extensions

      # @param legacy_version [String]
      # @param random [String]
      # @param legacy_session_id_echo [String]
      # @param cipher_suite [TTTLS13::CipherSuite]
      # @param legacy_compression_method [String]
      # @param extensions [TTTLS13::Message::Extensions]
      # rubocop: disable Metrics/ParameterLists
      def initialize(legacy_session_id_echo:, cipher_suite:, legacy_version: ProtocolVersion::TLS_1_2,
                     random: OpenSSL::Random.random_bytes(32),
                     legacy_compression_method: "\x00",
                     extensions: Extensions.new)
        @msg_type = HandshakeType::SERVER_HELLO
        @legacy_version = legacy_version
        @random = random
        @legacy_session_id_echo = legacy_session_id_echo
        @cipher_suite = cipher_suite
        @legacy_compression_method = legacy_compression_method
        @extensions = extensions
      end
      # rubocop: enable Metrics/ParameterLists

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
      # @raise [TTTLS13::Error::ErrorAlerts]
      #
      # @return [TTTLS13::Message::ServerHello]
      # rubocop: disable Metrics/AbcSize
      # rubocop: disable Metrics/MethodLength
      def self.deserialize(binary)
        raise Error::ErrorAlerts, :internal_error if binary.nil?
        raise Error::ErrorAlerts, :decode_error if binary.length < 39
        raise Error::ErrorAlerts, :internal_error \
          unless binary[0] == HandshakeType::SERVER_HELLO

        msg_len = Convert.bin2i(binary.slice(1, 3))
        legacy_version = binary.slice(4, 2)
        random = binary.slice(6, 32)
        lsid_len = Convert.bin2i(binary[38])
        legacy_session_id_echo = binary.slice(39, lsid_len)
        i = 39 + lsid_len
        cipher_suite = binary.slice(i, 2)
        i += 2
        legacy_compression_method = binary[i]
        i += 1
        exs_len = Convert.bin2i(binary.slice(i, 2))
        i += 2
        exs_bin = binary.slice(i, exs_len)
        if random == HRR_RANDOM
          msg_type = HandshakeType::HELLO_RETRY_REQUEST
        else
          msg_type = HandshakeType::SERVER_HELLO
        end
        extensions = Extensions.deserialize(exs_bin, msg_type)
        i += exs_len
        raise Error::ErrorAlerts, :decode_error unless i == msg_len + 4 &&
                                                       i == binary.length

        ServerHello.new(legacy_version:,
                        random:,
                        legacy_session_id_echo:,
                        cipher_suite:,
                        legacy_compression_method:,
                        extensions:)
      end

      # rubocop: enable Metrics/AbcSize
      # rubocop: enable Metrics/MethodLength
      # @return [Boolean]
      def hrr?
        @random == HRR_RANDOM
      end

      # @return [Boolean]
      def appearable_extensions?
        exs = @extensions.keys - APPEARABLE_SH_EXTENSIONS
        exs = @extensions.keys - APPEARABLE_HRR_EXTENSIONS if hrr?
        return true if exs.empty?

        !(exs - DEFINED_EXTENSIONS).empty?
      end

      # @return [Booelan]
      def negotiated_tls_1_3?
        sv = @extensions[Message::ExtensionType::SUPPORTED_VERSIONS]

        @legacy_version == Message::ProtocolVersion::TLS_1_2 &&
          (sv&.versions || []).first == Message::ProtocolVersion::TLS_1_3
      end

      # @return [Boolean]
      def downgraded?
        [DOWNGRADE_PROTECTION_TLS_1_2,
         DOWNGRADE_PROTECTION_TLS_1_1].include?(@random[-8..])
      end
    end
  end
end
