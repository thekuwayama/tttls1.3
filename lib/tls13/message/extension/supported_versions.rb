module TLS13
  module Message
    module Extension
      class SupportedVersions
        attr_accessor :extension_type
        attr_accessor :length
        attr_accessor :versions

        # @param versions [Array of Array of Integer]
        #
        # @return [TLS13::Message::Extension::SupportedVersions]
        def initialize(versions: [ProtocolVersion::TLS_1_3])
          @extension_type = ExtensionType::SUPPORTED_VERSIONS
          @versions = versions || []
          @length = 2 + @versions.length * 2
        end

        # @return [Array of Integer]
        def serialize
          binary = []
          binary += @extension_type
          binary += i2uint16(@length)
          binary += @versions.flatten
          binary
        end

        # @param binary [Array of Integer]
        #
        # @return [TLS13::Message::Extensions::SupportedVersions]
        def self.deserialize(binary)
          raise 'too short binary' if binary.nil? || binary.length < 2

          versions_len = arr2i([binary[0], binary[1]])
          itr = 2
          versions = []
          while itr < versions_len + 2
            versions << [binary[itr], binary[itr + 1]]
            itr += 2
          end
          SupportedVersions.new(versions: versions)
        end
      end
    end
  end
end
