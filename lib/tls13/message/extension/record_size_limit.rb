# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  using Refinements
  module Message
    module Extension
      class RecordSizeLimit
        attr_reader :extension_type
        attr_reader :record_size_limit

        # @param record_size_limit [Integer]
        #
        # @raise [RuntimeError]
        def initialize(record_size_limit)
          @extension_type = ExtensionType::RECORD_SIZE_LIMIT
          @record_size_limit = record_size_limit
          raise Error::InternalError if @record_size_limit < 64
        end

        # @return [String]
        def serialize
          binary = @record_size_limit.to_uint16

          @extension_type + binary.prefix_uint16_length
        end

        # @param binary [String]
        #
        # @raise [TLS13::Error::InternalError, TLSError]
        #
        # @return [TLS13::Message::Extensions::RecordSizeLimit,
        #          UnknownExtension]
        def self.deserialize(binary)
          raise Error::InternalError if binary.nil?

          if binary.length != 2
            return UnknownExtension.new(
              extension_type: ExtensionType::RECORD_SIZE_LIMIT,
              extension_data: binary
            )
          end
          record_size_limit = Convert.bin2i(binary)
          raise Error::TLSError, :illegal_parameter if record_size_limit < 64

          RecordSizeLimit.new(record_size_limit)
        end
      end
    end
  end
end
