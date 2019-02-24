Dir[File.dirname(__FILE__) + '/extension/*.rb'].each { |f| require f }

module TLS13
  module Message
    module ExtensionType
      SERVER_NAME                            = "\x00\x00".freeze
      MAX_FRAGMENT_LENGTH                    = "\x00\x01".freeze
      STATUS_REQUEST                         = "\x00\x05".freeze
      SUPPORTED_GROUPS                       = "\x00\x0a".freeze
      SIGNATURE_ALGORITHMS                   = "\x00\x0d".freeze
      USE_SRTP                               = "\x00\x0e".freeze
      HEARTBEAT                              = "\x00\x0f".freeze
      APPLICATION_LAYER_PROTOCOL_NEGOTIATION = "\x00\x10".freeze
      SIGNED_CERTIFICATE_TIMESTAMP           = "\x00\x12".freeze
      CLIENT_CERTIFICATE_TYPE                = "\x00\x13".freeze
      SERVER_CERTIFICATE_TYPE                = "\x00\x14".freeze
      PADDING                                = "\x00\x15".freeze
      RECORD_SIZE_LIMIT                      = "\x00\x1c".freeze
      PRE_SHARED_KEY                         = "\x00\x29".freeze
      EARLY_DATA                             = "\x00\x2a".freeze
      SUPPORTED_VERSIONS                     = "\x00\x2b".freeze
      COOKIE                                 = "\x00\x2c".freeze
      PSK_KEY_EXCHANGE_MODES                 = "\x00\x2d".freeze
      CERTIFICATE_AUTHORITIES                = "\x00\x2f".freeze
      OID_FILTERS                            = "\x00\x30".freeze
      POST_HANDSHAKE_AUTH                    = "\x00\x31".freeze
      SIGNATURE_ALGORITHMS_CERT              = "\x00\x32".freeze
      KEY_SHARE                              = "\x00\x33".freeze
    end

    class Extensions
      attr_accessor :length
      attr_accessor :extensions

      # @param extensions [Hash]
      #
      # @example
      #   Extensions.new(
      #     extensions: {
      #       ExtensionType::SUPPORTED_VERSIONS => SupportedVersions.new
      #     }
      #   )
      def initialize(extensions)
        @length = 0
        @extensions = extensions || {}
        @length = @extensions.map { |x| x.length + 4 }.sum
      end

      # @return [String]
      def serialize
        binary = ''
        binary += @length
        @extensions.each_value do |ex|
          binary += ex.serialize
        end
      end

      # @param binary [String]
      # @param msg_type [TLS13::Message::HandshakeType]
      #
      # @raise [RuntimeError]
      #
      # @return [TLS13::Message::Extensions]
      def self.deserialize(binary, msg_type)
        raise 'too short binary' if binary.nil? || binary.length < 2

        length = bin2i(binary.slice(0, 2))
        itr = 2
        extensions = {}
        while itr < length + 2
          extension_type = [binary[itr], binary[itr + 1]]
          itr += 2
          ex_len = bin2i(binary.slice(itr, 2))
          itr += 2
          serialized_extension = binary.slice(itr, ex_len)
          extensions[extension_type] \
          = deserialize_extension(serialized_extension,
                                  extension_type,
                                  msg_type)
          itr += ex_len
        end
        Extensions.new(extensions)
      end

      # @param extension_type [TLS13::Message::ExtensionType]
      #
      # @return [TLS13::Message::Extension::$Object, nil]
      def [](extension_type)
        key = bin2i(extension_type.slice(0, 2))
        @extensions[key]
      end

      # @param binary [String]
      # @param extension_type [TLS13::Message::ExtensionType]
      # @param msg_type [TLS13::Message::HandshakeType]
      #
      # @return [TLS13::Message::Extension::$Object, nil]
      # rubocop: disable Metrics/CyclomaticComplexity, Metrics/MethodLength
      def self.deserialize_extension(binary, extension_type, msg_type)
        return nil if binary.nil? || binary.empty?

        # TODO
        case extension_type
        when ExtensionType::SERVER_NAME
          return Extension::ServerName.deserialize(binary)
        when ExtensionType::SUPPORTED_GROUPS
          return Extension::SupportedGroups.deserialize(binary)
        when ExtensionType::SIGNATURE_ALGORITHMS
          return Extension::SignatureAlgorithms.deserialize(binary)
        when ExtensionType::RECORD_SIZE_LIMIT
          return Extension::RecordSizeLimit.deserialize(binary)
        when ExtensionType::SUPPORTED_VERSIONS
          return Extension::SupportedVersions.deserialize(binary)
        when ExtensionType::COOKIE
          return Extension::Cookie.deserialize(binary)
        when ExtensionType::PSK_KEY_EXCHANGE_MODES
          return Extension::PskKeyExchangeModes.deserialize(binary)
        when ExtensionType::SIGNATURE_ALGORITHMS_CERT
          return Extension::SignatureAlgorithmsCert.deserialize(binary)
        when ExtensionType::KEY_SHARE
          return Extension::KeyShare.deserialize(binary, msg_type)
        else
          return Extension::UknownExtension.deserialize(binary, extension_type)
        end
      end
      # rubocop: enable Metrics/CyclomaticComplexity, Metrics/MethodLength
    end
  end
end
