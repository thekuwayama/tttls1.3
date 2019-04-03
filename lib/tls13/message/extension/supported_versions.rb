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
        # @raise [TLS13::Error::TLSError]
        # rubocop: disable Metrics/CyclomaticComplexity
        def initialize(msg_type:, versions: DEFAULT_VERSIONS)
          @extension_type = ExtensionType::SUPPORTED_VERSIONS
          @msg_type = msg_type
          @versions = versions || []
          case @msg_type
          when HandshakeType::CLIENT_HELLO
            raise Error::TLSError, :internal_error \
              if @versions.empty? || @versions.length > 127
          when HandshakeType::SERVER_HELLO, HandshakeType::HELLO_RETRY_REQUEST
            raise Error::TLSError, :internal_error unless @versions.length == 1
          else
            raise Error::TLSError, :internal_error
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
        # @raise [TLS13::Error::TLSError]
        #
        # @return [TLS13::Message::Extensions::SupportedVersions,
        #          UnknownExtension]
        def self.deserialize(binary, msg_type)
          raise Error::TLSError, :internal_error if binary.nil?

          versions = []
          case msg_type
          when HandshakeType::CLIENT_HELLO
            versions = deserialize_versions(binary)
            if versions.nil? # unparsable versions
              return UnknownExtension.new(
                extension_type: ExtensionType::SUPPORTED_VERSIONS,
                extension_data: binary
              )
            end
          when HandshakeType::SERVER_HELLO, HandshakeType::HELLO_RETRY_REQUEST
            if binary.length != 2
              return UnknownExtension.new(
                extension_type: ExtensionType::SUPPORTED_VERSIONS,
                extension_data: binary
              )
            end
            versions << binary.slice(0, 2)
          else
            return UnknownExtension.new(
              extension_type: ExtensionType::SUPPORTED_VERSIONS,
              extension_data: binary
            )
          end
          SupportedVersions.new(msg_type: msg_type, versions: versions)
        end

        # @param binary [String]
        #
        # @raise [RuntimeError]
        #
        # @return [Array of String, nil]
        # rubocop: disable Metrics/CyclomaticComplexity
        def self.deserialize_versions(binary)
          raise Error::TLSError, :internal_error if binary.nil?

          return nil if binary.empty?

          versions_len = Convert.bin2i(binary[0])
          i = 1
          versions = []
          while i < versions_len + 1
            return nil if i + 2 > binary.length

            versions << binary.slice(i, 2)
            i += 2
          end
          return nil if i != binary.length || i != versions_len + 1

          versions
        end
        # rubocop: enable Metrics/CyclomaticComplexity
      end
    end
  end
end
