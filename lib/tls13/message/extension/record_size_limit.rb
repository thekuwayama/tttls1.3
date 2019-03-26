# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  module Message
    module Extension
      class RecordSizeLimit
        attr_reader :extension_type
        attr_reader :record_size_limit

        # @param record_size_limit [Integer]
        #
        # @raise [RuntimeError]
        def initialize(record_size_limit)
          raise 'invalid RecordSizeLimit' \
            if record_size_limit <= 64

          @extension_type = ExtensionType::RECORD_SIZE_LIMIT
          @record_size_limit = record_size_limit
        end

        # @return [String]
        def serialize
          binary = i2uint16(@record_size_limit)

          @extension_type + uint16_length_prefix(binary)
        end

        # @param binary [String]
        #
        # @raise [RuntimeError]
        #
        # @return [TLS13::Message::Extensions::RecordSizeLimit]
        def self.deserialize(binary)
          raise 'malformed binary' if binary.nil? || binary.length != 2

          record_size_limit = bin2i(binary)
          RecordSizeLimit.new(record_size_limit)
        end
      end
    end
  end
end
