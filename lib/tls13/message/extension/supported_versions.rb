# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  module Message
    module Extension
      class SupportedVersions
        attr_reader   :extension_type
        attr_accessor :length
        attr_accessor :versions

        # @param versions [Array of ProtocolVersion]
        def initialize(versions = [ProtocolVersion::TLS_1_3])
          @extension_type = ExtensionType::SUPPORTED_VERSIONS
          @versions = versions || ''
          @length = 1 + @versions.length * 2
        end

        # @return [String]
        def serialize
          binary = ''
          binary += @extension_type
          binary += i2uint16(@length)
          binary << @versions.length * 2
          binary += @versions.join
          binary
        end

        # @param binary [String]
        #
        # @raise [RuntimeError]
        #
        # @return [TLS13::Message::Extensions::SupportedVersions]
        def self.deserialize(binary)
          raise 'too short binary' if binary.nil? || binary.empty?

          versions_len = bin2i(binary[0])
          raise 'malformed binary' unless binary.length == versions_len + 1

          itr = 1
          versions = []
          while itr < versions_len + 1
            versions << binary.slice(itr, 2)
            itr += 2
          end
          raise 'malformed binary' unless itr == binary.length

          SupportedVersions.new(versions)
        end
      end
    end
  end
end
