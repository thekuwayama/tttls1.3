# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  module Message
    module Extension
      module NamedGroup
        SECP256R1 = "\x00\x17"
        SECP384R1 = "\x00\x18"
        SECP521R1 = "\x00\x19"
        X25519    = "\x00\x1d"
        X448      = "\x00\x1e"
        FFDHE2048 = "\x01\x00"
        FFDHE3072 = "\x01\x01"
        FFDHE4096 = "\x01\x02"
        FFDHE6144 = "\x01\x03"
        FFDHE8192 = "\x01\x04"
        # ffdhe_private_use "\x01\xfc" ~ "\x01\xff"
        # ecdhe_private_use "\xfe\x00" ~ "\xfe\xff"

        class << self
          # For secp256r1, secp384r1, and secp521r1
          #       struct {
          #           uint8 legacy_form = 4;
          #           opaque X[coordinate_length];
          #           opaque Y[coordinate_length];
          #       } UncompressedPointRepresentation;
          # @param group [TLS13::Message::Extension::NamedGroup]
          #
          # @return [Integer]
          # rubocop: disable Metrics/CyclomaticComplexity, Metrics/MethodLength
          def key_exchange_len(group)
            case group
            when SECP256R1
              65
            when SECP384R1
              97
            when SECP521R1
              133
            when X25519
              32
            when X448
              56
            when FFDHE2048
              256
            when FFDHE4096
              512
            when FFDHE6144
              768
            when FFDHE8192
              1024
            else
              raise 'unsupported NamedGroup'
            end
          end
          # rubocop: enable Metrics/CyclomaticComplexity, Metrics/MethodLength
        end
      end

      DEFALT_NAMED_GROUP_LIST = [NamedGroup::SECP256R1,
                                 NamedGroup::SECP384R1,
                                 NamedGroup::SECP521R1,
                                 NamedGroup::X25519].freeze

      class SupportedGroups
        attr_reader :extension_type
        attr_reader :named_group_list

        # @param named_group_list [Array of NamedGroup]
        #
        # @raise [RuntimeError]
        def initialize(named_group_list = DEFALT_NAMED_GROUP_LIST)
          @extension_type = ExtensionType::SUPPORTED_GROUPS
          @named_group_list = named_group_list || []
          raise 'invalid named_group_list' \
            if @named_group_list.empty? || @named_group_list.length >= 2**15 - 1
        end

        # @return [Integer]
        def length
          2 + @named_group_list.length * 2
        end

        # @return [String]
        def serialize
          binary = ''
          binary += @extension_type
          binary += i2uint16(length)
          binary += i2uint16(length - 2)
          binary += @named_group_list.join
          binary
        end

        # @param binary [String]
        #
        # @raise [RuntimeError]
        #
        # @return [TLS13::Message::Extension::SupportedGroups]
        def self.deserialize(binary)
          raise 'too short binary' if binary.nil? || binary.length < 2

          nglist_len = bin2i(binary.slice(0, 2))
          raise 'malformed binary' unless binary.length == nglist_len + 2

          itr = 2
          named_group_list = []
          while itr < nglist_len + 2
            named_group_list << binary.slice(itr, 2)
            itr += 2
          end
          raise 'malformed binary' unless itr == binary.length

          SupportedGroups.new(named_group_list)
        end
      end
    end
  end
end
