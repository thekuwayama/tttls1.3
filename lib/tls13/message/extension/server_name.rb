module TLS13
  module Message
    module Extension
      module NameType
        HOST_NAME = "\x00".freeze
      end

      class ServerName
        attr_accessor :extension_type
        attr_accessor :length
        attr_accessor :server_name

        # @param server_name [Hash]
        #
        # @example
        #   ServerName.new('example.com')
        def initialize(server_name)
          @extension_type = ExtensionType::SERVER_NAME
          @server_name = server_name
          @length = 5 + @server_name.length
        end

        # @return [Array of Integer]
        def serialize
          binary = ''
          binary += @extension_type
          binary += i2uint16(@length)
          binary += i2uint16(@length - 2)
          binary += NameType::HOST_NAME
          binary += i2uint16(@length - 5)
          binary += @server_name
          binary
        end

        # @param binary [Array of Integer]
        #
        # @raise [RuntimeError]
        #
        # @return [TLS13::Message::Extension::ServerName]
        def self.deserialize(binary)
          raise 'invalid binary' if binary.nil? || binary.length < 2

          snlist_len = bin2i(binary.slice(0, 2))
          raise 'malformed binary' unless snlist_len + 2 == binary.length

          raise 'unknown name_type' unless binary[2] == NameType::HOST_NAME

          sn_len = bin2i(binary.slice(3, 2))
          raise 'malformed binary' unless sn_len + 5 == binary.length

          server_name = binary.slice(5, sn_len)
          ServerName.new(server_name)
        end
      end
    end
  end
end
