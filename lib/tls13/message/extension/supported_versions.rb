# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  module Message
    module Extension
      class SupportedVersions
        attr_reader   :extension_type
        attr_accessor :msg_type
        attr_accessor :versions

        # @param msg_type [TLS13::Message::ContentType]
        # @param versions [Array of ProtocolVersion]
        #
        # @raise [RuntimeError]
        # rubocop: disable Metrics/CyclomaticComplexity
        def initialize(msg_type: nil, versions: [ProtocolVersion::TLS_1_3])
          @extension_type = ExtensionType::SUPPORTED_VERSIONS
          @msg_type = msg_type
          @versions = versions || []
          case @msg_type
          when HandshakeType::CLIENT_HELLO
            raise 'invalid versions.length' \
              if @versions.empty? || @versions.length > 127
          when HandshakeType::SERVER_HELLO, HandshakeType::HELLO_RETRY_REQUEST
            raise 'invalid versions.length' unless @versions.length == 1
          else
            raise 'invalid msg_type'
          end
        end
        # rubocop: enable Metrics/CyclomaticComplexity

        # @return [Integer]
        def length
          @versions.length * 2 \
          + (@msg_type == HandshakeType::CLIENT_HELLO ? 1 : 0)
        end

        # @return [String]
        def serialize
          binary = ''
          binary += @extension_type
          binary += i2uint16(length)
          binary += i2uint8(@versions.length * 2) \
            if @msg_type == HandshakeType::CLIENT_HELLO
          binary += @versions.join
          binary
        end

        # @param binary [String]
        # @param msg_type [TLS13::Message::HandshakeType]
        #
        # @raise [RuntimeError]
        #
        # @return [TLS13::Message::Extensions::SupportedVersions]
        def self.deserialize(binary, msg_type)
          versions = []
          case msg_type
          when HandshakeType::CLIENT_HELLO
            versions = deserialize_versions(binary)
          when HandshakeType::SERVER_HELLO, HandshakeType::HELLO_RETRY_REQUEST
            raise 'malformed binary' unless binary.length == 2

            versions << binary.slice(0, 2)
          else
            extension_type = ExtensionType::SUPPORTED_VERSION
            return UknownExtension.new(extension_type: extension_type,
                                       extension_data: binary)
          end
          SupportedVersions.new(msg_type: msg_type, versions: versions)
        end

        # @param binary [String]
        #
        # @raise [RuntimeError]
        #
        # @return [Array of String]
        def self.deserialize_versions(binary)
          raise 'too short binary' if binary.nil? || binary.empty?

          versions_len = bin2i(binary[0])
          itr = 1
          versions = []
          while itr < versions_len + 1
            versions << binary.slice(itr, 2)
            itr += 2
          end
          raise 'malformed binary' unless itr == binary.length \
                                          && itr == versions_len + 1

          versions
        end
      end
    end
  end
end
