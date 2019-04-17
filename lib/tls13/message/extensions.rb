# encoding: ascii-8bit
# frozen_string_literal: true

Dir[File.dirname(__FILE__) + '/extension/*.rb'].each { |f| require f }

module TLS13
  using Refinements
  module Message
    module ExtensionType
      SERVER_NAME                            = "\x00\x00"
      MAX_FRAGMENT_LENGTH                    = "\x00\x01"
      STATUS_REQUEST                         = "\x00\x05"
      SUPPORTED_GROUPS                       = "\x00\x0a"
      SIGNATURE_ALGORITHMS                   = "\x00\x0d"
      USE_SRTP                               = "\x00\x0e"
      HEARTBEAT                              = "\x00\x0f"
      APPLICATION_LAYER_PROTOCOL_NEGOTIATION = "\x00\x10"
      SIGNED_CERTIFICATE_TIMESTAMP           = "\x00\x12"
      CLIENT_CERTIFICATE_TYPE                = "\x00\x13"
      SERVER_CERTIFICATE_TYPE                = "\x00\x14"
      PADDING                                = "\x00\x15"
      RECORD_SIZE_LIMIT                      = "\x00\x1c"
      PRE_SHARED_KEY                         = "\x00\x29"
      EARLY_DATA                             = "\x00\x2a"
      SUPPORTED_VERSIONS                     = "\x00\x2b"
      COOKIE                                 = "\x00\x2c"
      PSK_KEY_EXCHANGE_MODES                 = "\x00\x2d"
      CERTIFICATE_AUTHORITIES                = "\x00\x2f"
      OID_FILTERS                            = "\x00\x30"
      POST_HANDSHAKE_AUTH                    = "\x00\x31"
      SIGNATURE_ALGORITHMS_CERT              = "\x00\x32"
      KEY_SHARE                              = "\x00\x33"
    end

    class Extensions < Hash
      # @param extensions [Array of TLS13::Message::Extension::$Object]
      #
      # @example
      #   Extensions.new([SupportedVersions.new, ServerName.new('example.com')]
      def initialize(extensions = [])
        extensions.each do |ex|
          super[ex.extension_type] = ex
        end
      end

      alias super_fetch fetch

      # @return [String]
      def serialize
        binary = ''
        exs_except_psk = values.reject do |ex|
          ex.extension_type == ExtensionType::PRE_SHARED_KEY
        end
        exs_except_psk.each do |ex|
          binary += ex.serialize
        end
        binary += super_fetch(ExtensionType::PRE_SHARED_KEY).serialize \
          if include?(ExtensionType::PRE_SHARED_KEY)
        binary.prefix_uint16_length
      end

      # @param binary [String]
      # @param msg_type [TLS13::Message::HandshakeType]
      #
      # @raise [TLS13::Error::ErrorAlerts]
      #
      # @return [TLS13::Message::Extensions]
      # rubocop: disable Metrics/CyclomaticComplexity
      def self.deserialize(binary, msg_type)
        raise Error::ErrorAlerts, :internal_error if binary.nil?

        extensions = []
        i = 0
        while i < binary.length
          raise Error::ErrorAlerts, :decode_error if i + 4 > binary.length

          extension_type = binary.slice(i, 2)
          i += 2
          ex_len = Convert.bin2i(binary.slice(i, 2))
          i += 2

          raise Error::ErrorAlerts, :decode_error if i + ex_len > binary.length

          ex_bin = binary.slice(i, ex_len)
          ex = deserialize_extension(ex_bin, extension_type, msg_type)
          if ex.nil?
            # ignore unparsable binary, but only transcript
            ex = Extension::UnknownExtension.new(extension_type, ex_bin)
          end
          extensions << ex
          i += ex_len
        end
        raise Error::ErrorAlerts, :decode_error unless i == binary.length

        Extensions.new(extensions)
      end
      # rubocop: enable Metrics/CyclomaticComplexity

      # @param key [TLS13::Message::ExtensionType]
      #
      # @return [TLS13::Message::Extension::$Object]
      def [](key)
        return nil if super_fetch(key, nil).is_a?(Extension::UnknownExtension)

        super_fetch(key, nil)
      end

      # @param key [TLS13::Message::ExtensionType]
      # @param default
      #
      # @return [TLS13::Message::Extension::$Object]
      def fetch(key, default = nil)
        return nil if super_fetch(key, nil).is_a?(Extension::UnknownExtension)

        super_fetch(key, default)
      end

      class << self
        private

        # NOTE:
        # deserialize_extension ignores unparsable extension.
        # Received unparsable binary, returns nil, doesn't raise
        # ErrorAlerts :decode_error.
        #
        # @param binary [String]
        # @param extension_type [TLS13::Message::ExtensionType]
        # @param msg_type [TLS13::Message::HandshakeType]
        #
        # @raise [TLS13::Error::ErrorAlerts]
        #
        # @return [TLS13::Message::Extension::$Object, nil]
        # rubocop: disable Metrics/CyclomaticComplexity
        def deserialize_extension(binary, extension_type, msg_type)
          raise Error::ErrorAlerts, :internal_error if binary.nil?

          case extension_type
          when ExtensionType::SERVER_NAME
            Extension::ServerName.deserialize(binary)
          when ExtensionType::SUPPORTED_GROUPS
            Extension::SupportedGroups.deserialize(binary)
          when ExtensionType::SIGNATURE_ALGORITHMS
            Extension::SignatureAlgorithms.deserialize(binary)
          when ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION
            Extension::Alpn..deserialize(binary)
          when ExtensionType::RECORD_SIZE_LIMIT
            Extension::RecordSizeLimit.deserialize(binary)
          when ExtensionType::EARLY_DATA
            Extension::EarlyDataIndication.deserialize(binary, msg_type)
          when ExtensionType::SUPPORTED_VERSIONS
            Extension::SupportedVersions.deserialize(binary, msg_type)
          when ExtensionType::COOKIE
            Extension::Cookie.deserialize(binary)
          when ExtensionType::PSK_KEY_EXCHANGE_MODES
            Extension::PskKeyExchangeModes.deserialize(binary)
          when ExtensionType::SIGNATURE_ALGORITHMS_CERT
            Extension::SignatureAlgorithmsCert.deserialize(binary)
          when ExtensionType::KEY_SHARE
            Extension::KeyShare.deserialize(binary, msg_type)
          else
            Extension::UnknownExtension.deserialize(binary, extension_type)
          end
        end
        # rubocop: enable Metrics/CyclomaticComplexity
      end
    end
  end
end
