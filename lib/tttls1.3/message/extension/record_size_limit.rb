# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  using Refinements
  module Message
    module Extension
      class RecordSizeLimit
        attr_reader :extension_type, :record_size_limit

        # @param record_size_limit [Integer]
        #
        # @raise [TTTLS13::Error::ErrorAlerts]
        def initialize(record_size_limit)
          @extension_type = ExtensionType::RECORD_SIZE_LIMIT
          @record_size_limit = record_size_limit
          raise Error::ErrorAlerts, :internal_error \
            if @record_size_limit < 64 || @record_size_limit > 2**14 + 1
        end

        # @return [String]
        def serialize
          binary = @record_size_limit.to_uint16

          @extension_type + binary.prefix_uint16_length
        end

        # @param binary [String]
        #
        # @raise [TTTLS13::Error::ErrorAlerts]
        #
        # @return [TTTLS13::Message::Extensions::RecordSizeLimit, nil]
        def self.deserialize(binary)
          raise Error::ErrorAlerts, :internal_error if binary.nil?

          return nil if binary.length != 2

          record_size_limit = Convert.bin2i(binary)
          raise Error::ErrorAlerts, :illegal_parameter if record_size_limit < 64

          RecordSizeLimit.new(record_size_limit)
        end
      end
    end
  end
end
