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

      # @param length [Integer]
      # @param extensions [Hash]
      #
      # @return [TLS13::Message::Extensions]
      def initialize(length: 0, extensions: {})
        @length = length
        @extensions = extensions
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
      #
      # @raise [RuntimeError]
      #
      # @return [TLS13::Message::Extensions]
      def self.deserialize(binary)
        raise 'Extensions: too short' if binary.nil? || binary.length < 2

        length = binary[0] << 8 + binary[1]
        itr = 2
        extensions = {}
        while itr < length + 2
          extension_type = [binary[itr], binary[itr + 1]]
          itr += 2
          l = [binary[itr], binary[itr + 1]]
          itr += 2
          extensions = binary.slice(itr, l)
          extensions[extension_type] \
          = deserialize_extension(extensions, extension_type)
          itr += l
        end
        Extensions.new(length: length, extensions: extensions)
      end

      # @param extension_type [Array of Integer]
      #
      # @return [TLS13::Message::Extension::$Object, nil]
      def [](extension_type)
        key = extension_type[0] << 8 + extension_type[1]
        @extensions[key]
      end

      # @param binary [Array of Integer]
      # @param extension_type [Array of Integer]
      #
      # @return [TLS13::Message::Extension::$Object]
      def self.deserialize_extension(binary, extension_type)
        return nil if binary.nil? || binary.empty?

        # TODO
        if extension_type == ExtensionType::SERVER_NAME
          return Extension::ServerName.deserialize(binary)
        end

        Extension::UknownExtension.deserialize(binary, extension_type)
      end
    end
  end
end
