# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  using Refinements
  module Message
    # https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-1
    APPEARABLE_CH_EXTENSIONS = [
      ExtensionType::SERVER_NAME,
      ExtensionType::MAX_FRAGMENT_LENGTH,
      ExtensionType::STATUS_REQUEST,
      ExtensionType::SUPPORTED_GROUPS,
      ExtensionType::SIGNATURE_ALGORITHMS,
      ExtensionType::USE_SRTP,
      ExtensionType::HEARTBEAT,
      ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
      ExtensionType::SIGNED_CERTIFICATE_TIMESTAMP,
      ExtensionType::CLIENT_CERTIFICATE_TYPE,
      ExtensionType::SERVER_CERTIFICATE_TYPE,
      ExtensionType::PADDING,
      ExtensionType::COMPRESS_CERTIFICATE,
      ExtensionType::RECORD_SIZE_LIMIT,
      ExtensionType::PWD_PROTECT,
      ExtensionType::PWD_CLEAR,
      ExtensionType::PASSWORD_SALT,
      ExtensionType::PRE_SHARED_KEY,
      ExtensionType::EARLY_DATA,
      ExtensionType::SUPPORTED_VERSIONS,
      ExtensionType::COOKIE,
      ExtensionType::PSK_KEY_EXCHANGE_MODES,
      ExtensionType::CERTIFICATE_AUTHORITIES,
      ExtensionType::POST_HANDSHAKE_AUTH,
      ExtensionType::SIGNATURE_ALGORITHMS_CERT,
      ExtensionType::KEY_SHARE,
      ExtensionType::ENCRYPTED_CLIENT_HELLO
    ].freeze
    private_constant :APPEARABLE_CH_EXTENSIONS

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
      # @param cipher_suites [TTTLS13::CipherSuites]
      # @param legacy_compression_methods [Array of String]
      # @param extensions [TTTLS13::Message::Extensions]
      # rubocop: disable Metrics/ParameterLists
      def initialize(legacy_version: ProtocolVersion::TLS_1_2,
                     random: OpenSSL::Random.random_bytes(32),
                     legacy_session_id: OpenSSL::Random.random_bytes(32),
                     cipher_suites:,
                     legacy_compression_methods: ["\x00"],
                     extensions: Extensions.new)
        @msg_type = HandshakeType::CLIENT_HELLO
        @legacy_version = legacy_version
        @random = random
        @legacy_session_id = legacy_session_id
        @cipher_suites = cipher_suites
        @legacy_compression_methods = legacy_compression_methods
        @extensions = extensions
      end
      # rubocop: enable Metrics/ParameterLists

      # @return [String]
      def serialize
        binary = ''
        binary += @legacy_version
        binary += @random
        binary += @legacy_session_id.prefix_uint8_length
        binary += @cipher_suites.serialize
        binary += @legacy_compression_methods.join.prefix_uint8_length
        binary += @extensions.serialize

        @msg_type + binary.prefix_uint24_length
      end

      # @param binary [String]
      #
      # @raise [TTTLS13::Error::ErrorAlerts]
      #
      # @return [TTTLS13::Message::ClientHello]
      # rubocop: disable Metrics/AbcSize
      # rubocop: disable Metrics/MethodLength
      def self.deserialize(binary)
        raise Error::ErrorAlerts, :internal_error if binary.nil?
        raise Error::ErrorAlerts, :decode_error if binary.length < 39
        raise Error::ErrorAlerts, :internal_error \
          unless binary[0] == HandshakeType::CLIENT_HELLO

        msg_len = Convert.bin2i(binary.slice(1, 3))
        legacy_version = binary.slice(4, 2)
        random = binary.slice(6, 32)
        lsid_len = Convert.bin2i(binary[38])
        legacy_session_id = binary.slice(39, lsid_len)
        i = 39 + lsid_len
        cs_len = Convert.bin2i(binary.slice(i, 2))
        i += 2
        cs_bin = binary.slice(i, cs_len)
        cipher_suites = CipherSuites.deserialize(cs_bin)
        i += cs_len
        cm_len = Convert.bin2i(binary[i])
        i += 1
        legacy_compression_methods = binary.slice(i, cm_len).split('')
        i += cm_len
        exs_len = Convert.bin2i(binary.slice(i, 2))
        i += 2
        exs_bin = binary.slice(i, exs_len)
        extensions = Extensions.deserialize(exs_bin,
                                            HandshakeType::CLIENT_HELLO)
        i += exs_len
        raise Error::ErrorAlerts, :decode_error unless i == msg_len + 4 &&
                                                       i == binary.length

        ClientHello.new(legacy_version: legacy_version,
                        random: random,
                        legacy_session_id: legacy_session_id,
                        cipher_suites: cipher_suites,
                        legacy_compression_methods: legacy_compression_methods,
                        extensions: extensions)
      end
      # rubocop: enable Metrics/AbcSize
      # rubocop: enable Metrics/MethodLength

      # @return [Boolean]
      def appearable_extensions?
        exs = @extensions.keys - APPEARABLE_CH_EXTENSIONS
        return true if exs.empty?

        !(exs - DEFINED_EXTENSIONS).empty?
      end

      # @return [Boolean]
      def negotiated_tls_1_3?
        sv = @extensions[ExtensionType::SUPPORTED_VERSIONS]

        @legacy_version == ProtocolVersion::TLS_1_2 &&
          (sv&.versions || []).include?(ProtocolVersion::TLS_1_3)
      end

      # @return [Boolean]
      def valid_key_share?
        ks = @extensions[Message::ExtensionType::KEY_SHARE]
        ks_groups = ks&.key_share_entry&.map(&:group) || []
        sg = @extensions[Message::ExtensionType::SUPPORTED_GROUPS]
        sg_groups = sg&.named_group_list || []

        # Each KeyShareEntry value MUST correspond to a group offered in the
        # "supported_groups" extension and MUST appear in the same order.
        #
        # Clients MUST NOT offer multiple KeyShareEntry values for the same
        # group.
        (ks_groups - sg_groups).empty? &&
          sg_groups.filter { |g| ks_groups.include?(g) } == ks_groups &&
          ks_groups.uniq == ks_groups
      end
    end
  end
end
