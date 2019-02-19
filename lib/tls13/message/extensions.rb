Dir[File.dirname(__FILE__) + '/extension/*.rb'].each { |f| require f }

module TLS13
  module Message
    module ExtensionType
      SERVER_NAME                            = [0x00, 0x00].freeze
      MAX_FRAGMENT_LENGTH                    = [0x00, 0x01].freeze
      STATUS_REQUEST                         = [0x00, 0x05].freeze
      SUPPORTED_GROUPS                       = [0x00, 0x0a].freeze
      SIGNATURE_ALGORITHMS                   = [0x00, 0x0d].freeze
      USE_SRTP                               = [0x00, 0x0e].freeze
      HEARTBEAT                              = [0x00, 0x0f].freeze
      APPLICATION_LAYER_PROTOCOL_NEGOTIATION = [0x00, 0x10].freeze
      SIGNED_CERTIFICATE_TIMESTAMP           = [0x00, 0x12].freeze
      CLIENT_CERTIFICATE_TYPE                = [0x00, 0x13].freeze
      SERVER_CERTIFICATE_TYPE                = [0x00, 0x14].freeze
      PADDING                                = [0x00, 0x15].freeze
      PRE_SHARED_KEY                         = [0x00, 0x29].freeze
      EARLY_DATA                             = [0x00, 0x2a].freeze
      SUPPORTED_VERSIONS                     = [0x00, 0x2b].freeze
      COOKIE                                 = [0x00, 0x2c].freeze
      PSK_KEY_EXCHANGE_MODES                 = [0x00, 0x2d].freeze
      CERTIFICATE_AUTHORITIES                = [0x00, 0x2f].freeze
      OID_FILTERS                            = [0x00, 0x30].freeze
      POST_HANDSHAKE_AUTH                    = [0x00, 0x31].freeze
      SIGNATURE_ALGORITHMS_CERT              = [0x00, 0x32].freeze
      KEY_SHARE                              = [0x00, 0x33].freeze
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
      def initialize(extensions: {})
        @length = 0
        @extensions = extensions
        @length = @extensions.map { |x| x.length + 4 }.sum \
          unless @extensions.nil? || @extensions.empty?
      end

      # @return [Array of Integer]
      def serialize
        binary = []
        binary += @length
        @extensions.each_value do |ex|
          binary += ex.serialize
        end
      end

      # @param binary [Array of Integer]
      # @param msg_type [TLS13::Message::HandshakeType]
      #
      # @raise [RuntimeError]
      #
      # @return [TLS13::Message::Extensions]
      def self.deserialize(binary, msg_type)
        raise 'too short binary' if binary.nil? || binary.length < 2

        length = arr2i([binary[0], binary[1]])
        itr = 2
        extensions = {}
        while itr < length + 2
          extension_type = [binary[itr], binary[itr + 1]]
          itr += 2
          ex_len = arr2i([binary[itr], binary[itr + 1]])
          itr += 2
          serialized_extension = binary.slice(itr, ex_len)
          extensions[extension_type] \
          = deserialize_extension(serialized_extension,
                                  extension_type,
                                  msg_type)
          itr += ex_len
        end
        Extensions.new(extensions: extensions)
      end

      # @param extension_type [TLS13::Message::ExtensionType]
      #
      # @return [TLS13::Message::Extension::$Object, nil]
      def [](extension_type)
        key = arr2i([extension_type[0], extension_type[1]])
        @extensions[key]
      end

      # @param binary [Array of Integer]
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
