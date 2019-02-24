module TLS13
  module Message
    module Extension
      class UknownExtension
        attr_accessor :extension_type
        attr_accessor :length
        attr_accessor :extension_data

        # @param extension_type [Array of Integer]
        # @param extension_data [Array of Integer]
        #
        # @raise [RuntimeError]
        def initialize(extension_type: nil, extension_data: nil)
          raise 'extension_type is required argument' if extension_type.nil?

          @extension_type = extension_type
          @extension_data = extension_data || ''
          @length = @extension_data.length
        end

        # @return [Array of Integer]
        def serialize
          binary = ''
          binary += @extension_type
          binary += i2uint16(@length)
          binary.force_encoding('ASCII-8BIT')
          binary += @extension_data
          binary
        end

        # @param binary [Array of Integer]
        # @param extension_type [Array of Integer]
        #
        # @return [TLS13::Message::Extension::UknownExtension]
        def self.deserialize(binary, extension_type)
          UknownExtension.new(extension_type: extension_type,
                              extension_data: binary)
        end
      end
    end
  end
end
