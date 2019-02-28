# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  module Message
    module Extension
      module NameType
        HOST_NAME = "\x00"
      end

      # NOTE:
      # The extension_data field SHALL be empty when @server_name is empty.
      # Then, serialized extension_data is
      #
      # 00 00 00 00
      #
      # https://tools.ietf.org/html/rfc6066#section-3
      class ServerName
        attr_reader   :extension_type
        attr_accessor :server_name

        # @param server_name [String]
        #
        # @raise [RuntimeError]
        #
        # @example
        #   ServerName.new('example.com')
        def initialize(server_name)
          @extension_type = ExtensionType::SERVER_NAME
          @server_name = server_name || ''
          raise 'too long HostName' \
            if @server_name.length > 2**16 - 5
        end

        # @return [Integer]
        def length
          return 0 if @server_name.empty?

          5 + @server_name.length
        end

        # @return [String]
        def serialize
          return "\x00\x00\x00\x00" if length.zero?

          binary = ''
          binary += @extension_type
          binary += i2uint16(length)
          binary += i2uint16(length - 2)
          binary += NameType::HOST_NAME
          binary += i2uint16(length - 5)
          binary += @server_name
          binary
        end

        # @param binary [String]
        #
        # @raise [RuntimeError]
        #
        # @return [TLS13::Message::Extension::ServerName]
        def self.deserialize(binary)
          raise 'too short binary' if binary.nil? || binary.length == 1

          return ServerName.new('') if binary.empty?

          deserialize_host_name(binary)
        end

        # @param binary [String]
        #
        # @raise [RuntimeError]
        #
        # @return [TLS13::Message::Extension::ServerName]
        def self.deserialize_host_name(binary)
          raise 'too short binary' if binary.nil? || binary.length < 2

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
