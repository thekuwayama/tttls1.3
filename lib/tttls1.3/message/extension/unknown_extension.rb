# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  using Refinements
  module Message
    module Extension
      # Client/Server MUST ignore unrecognized extensions,
      # but transcript MUST include unrecognized extensions.
      class UnknownExtension
        attr_reader :extension_type, :extension_data

        # @param extension_type [String]
        # @param extension_data [String]
        def initialize(extension_type:, extension_data: '')
          @extension_type = extension_type
          @extension_data = extension_data || ''
        end

        # @return [String]
        def serialize
          @extension_type + @extension_data.prefix_uint16_length
        end

        # @param binary [String]
        # @param extension_type [String]
        #
        # @return [TTTLS13::Message::Extension::UnknownExtension]
        def self.deserialize(binary, extension_type)
          UnknownExtension.new(extension_type:,
                               extension_data: binary)
        end
      end
    end
  end
end
