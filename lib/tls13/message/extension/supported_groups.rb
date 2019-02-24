module TLS13
  module Message
    module Extension
      module NamedGroup
        SECP256R1 = "\x00\x17".freeze
        SECP384R1 = "\x00\x18".freeze
        SECP521R1 = "\x00\x19".freeze
        X25519    = "\x00\x1d".freeze
        X448      = "\x00\x1e".freeze
        FFDHE2048 = "\x01\x00".freeze
        FFDHE3072 = "\x01\x01".freeze
        FFDHE4096 = "\x01\x02".freeze
        FFDHE6144 = "\x01\x03".freeze
        FFDHE8192 = "\x01\x04".freeze
        # ffdhe_private_use "\x01\xfc" ~ "\x01\xff"
        # ecdhe_private_use "\xfe\x00" ~ "\xfe\xff"
      end

      DEFALT_NAMED_GROUP_LIST = [NamedGroup::SECP256R1,
                                 NamedGroup::SECP384R1,
                                 NamedGroup::SECP521R1,
                                 NamedGroup::X25519].freeze
      class SupportedGroups
        attr_accessor :extension_type
        attr_accessor :length
        attr_accessor :named_group_list

        # @param named_group_list [Array of NamedGroup]
        def initialize(named_group_list = DEFALT_NAMED_GROUP_LIST)
          @extension_type = ExtensionType::SUPPORTED_GROUPS
          @named_group_list = named_group_list || []
          @length = 2 + @named_group_list.length * 2
        end

        # @return [Array of Integer]
        def serialize
          binary = ''
          binary += @extension_type
          binary += i2uint16(@length)
          binary += @named_group_list.join
          binary
        end

        # @param binary [Array of Integer]
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
          SupportedGroups.new(named_group_list)
        end
      end
    end
  end
end
