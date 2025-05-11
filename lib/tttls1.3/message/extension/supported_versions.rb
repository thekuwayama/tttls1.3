# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  using Refinements
  module Message
    module Extension
      class SupportedVersions
        attr_reader :extension_type, :msg_type, :versions

        # @param msg_type [TTTLS13::Message::ContentType]
        # @param versions [Array of ProtocolVersion]
        #
        # @raise [TTTLS13::Error::ErrorAlerts]
        def initialize(msg_type:, versions: DEFAULT_VERSIONS)
          @extension_type = ExtensionType::SUPPORTED_VERSIONS
          @msg_type = msg_type
          @versions = versions || []
          case @msg_type
          when HandshakeType::CLIENT_HELLO
            raise Error::ErrorAlerts, :internal_error \
              if @versions.empty? || @versions.length > 127
          when HandshakeType::SERVER_HELLO, HandshakeType::HELLO_RETRY_REQUEST
            raise Error::ErrorAlerts, :internal_error \
              unless @versions.length == 1
          else
            raise Error::ErrorAlerts, :internal_error
          end
        end

        # @return [String]
        def serialize
          binary = ''
          binary += (@versions.length * 2).to_uint8 \
            if @msg_type == HandshakeType::CLIENT_HELLO
          binary += @versions.join

          @extension_type + binary.prefix_uint16_length
        end

        # @param binary [String]
        # @param msg_type [TTTLS13::Message::HandshakeType]
        #
        # @raise [TTTLS13::Error::ErrorAlerts]
        #
        # @return [TTTLS13::Message::Extensions::SupportedVersions, nil]
        def self.deserialize(binary, msg_type)
          raise Error::ErrorAlerts, :internal_error if binary.nil?

          versions = []
          case msg_type
          when HandshakeType::CLIENT_HELLO
            versions = deserialize_versions(binary)
            return nil if versions.nil? # unparsable versions

          when HandshakeType::SERVER_HELLO, HandshakeType::HELLO_RETRY_REQUEST
            return nil if binary.length != 2

            versions << binary.slice(0, 2)
          else
            return nil
          end
          SupportedVersions.new(msg_type:, versions:)
        end

        # @param binary [String]
        #
        # @raise [TTTLS13::Error::ErrorAlerts]
        #
        # @return [Array of String, nil]
        def self.deserialize_versions(binary)
          raise Error::ErrorAlerts, :internal_error if binary.nil?

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
      end
    end
  end
end
