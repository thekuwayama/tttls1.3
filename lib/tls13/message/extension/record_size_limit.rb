module TLS13
  module Message
    module Extension
      class RecordSizeLimit
        attr_accessor :extension_type
        attr_accessor :length
        attr_accessor :record_size_limit

        # @raise [RuntimeError]
        #
        # @param record_size_limit [Integer]
        def initialize(record_size_limit)
          raise 'invalid record_size_limit' \
            if record_size_limit <= 64

          @extension_type = ExtensionType::RECORD_SIZE_LIMIT
          @record_size_limit = record_size_limit
          @length = 2
        end

        # @return [Array of Integer]
        def serialize
          binary = []
          binary += @extension_type
          binary += i2uint16(@length)
          binary += i2uint16(@record_size_limit)
          binary
        end

        # @param binary [Array of Integer]
        #
        # @raise [RuntimeError]
        #
        # @return [TLS13::Message::Extensions::RecordSizeLimit]
        def self.deserialize(binary)
          raise 'malformed binary' if binary.nil? || binary.length != 2

          record_size_limit = arr2i(binary)
          RecordSizeLimit.new(record_size_limit)
        end
      end
    end
  end
end
