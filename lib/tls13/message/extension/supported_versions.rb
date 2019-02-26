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
        def initialize(msg_type: ContentType::INVALID,
                       versions: [ProtocolVersion::TLS_1_3])
          @extension_type = ExtensionType::SUPPORTED_VERSIONS
          @msg_type = msg_type
          raise 'invalid msg_type' \
            if @msg_type != HandshakeType::CLIENT_HELLO \
               && @msg_type != HandshakeType::SERVER_HELLO \
               && @msg_type != HandshakeType::HELLO_RETRY_REQUEST

          @versions = versions || []
        end

        # @raise [RuntimeError]
        #
        # @return [Integer]
        def length
          case @msg_type
          when HandshakeType::CLIENT_HELLO
            1 + @versions.length * 2
          when HandshakeType::SERVER_HELLO, HandshakeType::HELLO_RETRY_REQUEST
            2
          else
            raise 'invalid msg_type'
          end
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
            raise 'too short binary' if binary.nil? || binary.empty?

            versions_len = bin2i(binary[0])
            itr = 1
            while itr < versions_len + 1
              versions << binary.slice(itr, 2)
              itr += 2
            end
            raise 'malformed binary' unless itr == binary.length \
                                            && itr == versions_len + 1
          when HandshakeType::SERVER_HELLO, HandshakeType::HELLO_RETRY_REQUEST
            raise 'malformed binary' unless binary.length == 2

            versions << binary.slice(0, 2)
          else
            return UknownExtension.new(extension_type: ExtensionType::SUPPORTED_VERSIONS,
                                       extension_data: binary)
          end
          SupportedVersions.new(msg_type: msg_type, versions: versions)
        end
      end
    end
  end
end
