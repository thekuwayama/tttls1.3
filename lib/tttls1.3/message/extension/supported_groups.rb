# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  using Refinements
  module Message
    module Extension
      class SupportedGroups
        attr_reader :extension_type
        attr_reader :named_group_list

        # @param named_group_list [Array of NamedGroup]
        #
        # @raise [TTTLS13::Error::ErrorAlerts]
        def initialize(named_group_list)
          @extension_type = ExtensionType::SUPPORTED_GROUPS
          @named_group_list = named_group_list || []
          raise Error::ErrorAlerts, :internal_error \
            if @named_group_list.empty? || @named_group_list.length >= 2**15 - 1
        end

        # @return [String]
        def serialize
          binary = @named_group_list.join.prefix_uint16_length

          @extension_type + binary.prefix_uint16_length
        end

        # @param binary [String]
        #
        # @raise [TTTLS13::Error::ErrorAlerts]
        #
        # @return [TTTLS13::Message::Extension::SupportedGroups, nil]
        # rubocop: disable Metrics/CyclomaticComplexity
        def self.deserialize(binary)
          raise Error::ErrorAlerts, :internal_error if binary.nil?

          return nil if binary.length < 2

          nglist_len = Convert.bin2i(binary.slice(0, 2))
          i = 2
          named_group_list = []
          while i < nglist_len + 2
            return nil if i + 2 > binary.length

            named_group_list << binary.slice(i, 2)
            i += 2
          end
          return nil unless i == binary.length &&
                            nglist_len + 2 == binary.length

          SupportedGroups.new(named_group_list)
        end
        # rubocop: enable Metrics/CyclomaticComplexity
      end
    end
  end
end
