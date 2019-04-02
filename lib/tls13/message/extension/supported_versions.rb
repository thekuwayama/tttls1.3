# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  using Refinements
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
        def initialize(msg_type:, versions: [ProtocolVersion::TLS_1_3])
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
            raise 'invalid HandshakeType'
          end
        end
        # rubocop: enable Metrics/CyclomaticComplexity

        # @return [String]
        def serialize
          binary = ''
          binary += (@versions.length * 2).to_uint8 \
            if @msg_type == HandshakeType::CLIENT_HELLO
          binary += @versions.join

          @extension_type + binary.prefix_uint16_length
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
            return UnknownExtension.new(extension_type: extension_type,
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

          versions_len = Convert.bin2i(binary[0])
          i = 1
          versions = []
          while i < versions_len + 1
            versions << binary.slice(i, 2)
            i += 2
          end
          raise 'malformed binary' unless i == binary.length \
                                          && i == versions_len + 1

          versions
        end
      end
    end
  end
end
