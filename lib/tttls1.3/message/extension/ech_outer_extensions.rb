# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  using Refinements
  module Message
    module Extension
      # NOTE:
      #     ExtensionType OuterExtensions<2..254>;
      class ECHOuterExtensions
        attr_reader :extension_type
        attr_reader :outer_extensions

        # @param outer_extensions [Array of TTTLS13::Message::ExtensionType]
        def initialize(outer_extensions)
          @extension_type = ExtensionType::ECH_OUTER_EXTENSIONS
          @outer_extensions = outer_extensions
        end

        # @raise [TTTLS13::Error::ErrorAlerts]
        #
        # @return [String]
        def serialize
          binary = @outer_extensions.join.prefix_uint8_length
          @extension_type + binary.prefix_uint16_length
        end

        # @param binary [String]
        #
        # @raise [TTTLS13::Error::ErrorAlerts]
        #
        # @return [TTTLS13::Message::Extensions::ECHOuterExtensions]
        def self.deserialize(binary)
          raise Error::ErrorAlerts, :internal_error if binary.nil?

          return nil if binary.length < 2

          exlist_len = Convert.bin2i(binary.slice(0, 1))
          i = 1
          outer_extensions = []
          while i < exlist_len + 1
            outer_extensions << binary.slice(i, 2)
            i += 2
          end
          return nil unless outer_extensions.length * 2 == exlist_len

          ECHOuterExtensions.new(outer_extensions)
        end
      end
    end
  end
end
