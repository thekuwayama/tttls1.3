require 'set'

module TLS13
  module Message
    module Extension
      module NameType
        HOST_NAME = 0
      end

      NAME_TYPE_ALLVALUE = NameType.constants.map(&NameType.method(:const_get))
                                   .to_set

      class ServerName
        attr_accessor :extension_type
        attr_accessor :length
        attr_accessor :server_name

        # @param server_name [Hash]
        #
        # @raise [RuntimeError]
        #
        # @return [TLS13::Message::Extension::ServerName]
        #
        # @example
        #   ServerName.new(
        #     server_name: { NameType::HOST_NAME => 'example.com' }
        #   )
        def initialize(server_name: {})
          @extension_type = ExtensionType::SERVER_NAME
          raise 'unknown name_type' unless
            server_name.keys.to_set.subset?(NAME_TYPE_ALLVALUE)

          @server_name = server_name
          @length = 0
          @server_name.each do |name_type, value|
            if name_type == NameType::HOST_NAME
              @length += (2 + 1 + 2)
              @length += value.length
            end
          end
        end

        # @return [Array of Integer]
        def serialize
          binary = []
          binary += @extension_type
          binary += [@length / (1 << 8), @length % (1 << 8)]
          @server_name.each do |name_type, value|
            binary << name_type
            if name_type == NameType::HOST_NAME # rubocop:disable all
              binary += value.bytes
            end
          end
          binary
        end

        # @param binary [Array of Integer]
        #
        # @raise [RuntimeError]
        #
        # @return [TLS13::Message::Extensions]
        def self.deserialize(binary)
          raise 'invalid binary' if binary.nil? || binary.length < 2

          snlist_len = (binary[0] << 8) + binary[1]
          raise 'invalid binary' unless snlist_len + 2 == binary.length

          server_name = {}
          itr = 2
          while itr < snlist_len + 2
            name_type = binary[itr]
            itr += 1
            if name_type == NameType::HOST_NAME
              l = (binary[itr] << 8) + binary[itr + 1]
              itr += 2
              host_name = binary.slice(itr, l).map(&:chr).join
              itr += l
              server_name[name_type] = host_name
            else
              server_name[name_type] = binary[itr..-1]
              break
            end
          end
          ServerName.new(server_name: server_name)
        end
      end
    end
  end
end
