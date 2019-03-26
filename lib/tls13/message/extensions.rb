# encoding: ascii-8bit
# frozen_string_literal: true

Dir[File.dirname(__FILE__) + '/extension/*.rb'].each { |f| require f }

module TLS13
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

      # @return [String]
      def serialize
        binary = ''
        exs_except_psk = values.reject do |ex|
          ex.extension_type == ExtensionType::PRE_SHARED_KEY
        end
        exs_except_psk.each do |ex|
          binary += ex.serialize
        end
        binary += self[ExtensionType::PRE_SHARED_KEY].serialize \
          if key?(ExtensionType::PRE_SHARED_KEY)
        uint16_length_prefix(binary)
      end

      # @param binary [String]
      # @param msg_type [TLS13::Message::HandshakeType]
      #
      # @raise [RuntimeError]
      #
      # @return [TLS13::Message::Extensions]
      def self.deserialize(binary, msg_type)
        raise 'too short binary' if binary.nil?

        extensions = []
        itr = 0
        while itr < binary.length
          extension_type = binary.slice(itr, 2)
          itr += 2
          ex_len = bin2i(binary.slice(itr, 2))
          itr += 2
          ex_bin = binary.slice(itr, ex_len)
          extensions << deserialize_extension(ex_bin,
                                              extension_type,
                                              msg_type)
          itr += ex_len
        end
        raise 'malformed binary' unless itr == binary.length

        Extensions.new(extensions)
      end

      # @param binary [String]
      # @param extension_type [TLS13::Message::ExtensionType]
      # @param msg_type [TLS13::Message::HandshakeType]
      #
      # @return [TLS13::Message::Extension::$Object, nil]
      # rubocop: disable Metrics/CyclomaticComplexity
      def self.deserialize_extension(binary, extension_type, msg_type)
        # TODO
        case extension_type
        when ExtensionType::SERVER_NAME
          Extension::ServerName.deserialize(binary)
        when ExtensionType::SUPPORTED_GROUPS
          Extension::SupportedGroups.deserialize(binary)
        when ExtensionType::SIGNATURE_ALGORITHMS
          Extension::SignatureAlgorithms.deserialize(binary)
        when ExtensionType::RECORD_SIZE_LIMIT
          Extension::RecordSizeLimit.deserialize(binary)
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
          Extension::UknownExtension.deserialize(binary, extension_type)
        end
      end
      # rubocop: enable Metrics/CyclomaticComplexity
    end
  end
end
