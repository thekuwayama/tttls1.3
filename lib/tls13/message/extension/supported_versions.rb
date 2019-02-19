module TLS13
  module Message
    module Extension
      class SupportedVersions
        attr_accessor :extension_type
        attr_accessor :length
        attr_accessor :versions

        # @param versions [Array of ProtocolVersion]
        def initialize(versions: [ProtocolVersion::TLS_1_3])
          @extension_type = ExtensionType::SUPPORTED_VERSIONS
          @versions = versions || []
          @length = 1 + @versions.length * 2
        end

        # @return [Array of Integer]
        def serialize
          binary = []
          binary += @extension_type
          binary += i2uint16(@length)
          binary << @versions.length * 2
          binary += @versions.flatten
          binary
        end

        # @param binary [Array of Integer]
        #
        # @raise [RuntimeError]
        #
        # @return [TLS13::Message::Extensions::SupportedVersions]
        def self.deserialize(binary)
          raise 'too short binary' if binary.nil? || binary.empty?

          versions_len = binary[0]
          itr = 1
          versions = []
          while itr < versions_len + 1
            versions << [binary[itr], binary[itr + 1]]
            itr += 2
          end
          SupportedVersions.new(versions: versions)
        end
      end
    end
  end
end
