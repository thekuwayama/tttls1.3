module TLS13
  module Message
    module Extension
      module NamedGroup
        SECP256R1 = [0x00, 0x17].freeze
        SECP384R1 = [0x00, 0x18].freeze
        SECP521R1 = [0x00, 0x19].freeze
        X25519    = [0x00, 0x1d].freeze
        X448      = [0x00, 0x1e].freeze
        FFDHE2048 = [0x01, 0x00].freeze
        FFDHE3072 = [0x01, 0x01].freeze
        FFDHE4096 = [0x01, 0x02].freeze
        FFDHE6144 = [0x01, 0x03].freeze
        FFDHE8192 = [0x01, 0x04].freeze
        # ffdhe_private_use [0x01, 0xfc] ~ [0x01, 0xff]
        # ecdhe_private_use [0xfe, 0x00] ~ [0xfe, 0xff]
      end

      class SupportedGroups
        attr_accessor :extension_type
        attr_accessor :length
        attr_accessor :named_group_list

        # @param named_group_list [Array of Array of Integer]
        #
        # @return [TLS13::Message::Extension::SupportedGroups]
        def initialize(named_group_list: [NamedGroup::SECP256R1,
                                          NamedGroup::SECP384R1,
                                          NamedGroup::SECP521R1,
                                          NamedGroup::X25519])
          @extension_type = ExtensionType::SUPPORTED_GROUPS
          @named_group_list = named_group_list || []
          @length = 2 + @named_group_list.length * 2
        end

        # @return [Array of Integer]
        def serialize
          binary = []
          binary += @extension_type
          binary += i2uint16(@length)
          binary += @named_group_list.flatten
          binary
        end

        # @param binary [Array of Integer]
        #
        # @return [TLS13::Message::Extension::SupportedGroups]
        def self.deserialize(binary)
          raise 'too short binary' if binary.nil? || binary.length < 2

          nglist_len = arr2i([binary[0], binary[1]])
          itr = 2
          named_group_list = []
          while itr < nglist_len + 2
            named_group_list << [binary[itr], binary[itr + 1]]
            itr += 2
          end
          SupportedGroups.new(named_group_list: named_group_list)
        end
      end
    end
  end
end
