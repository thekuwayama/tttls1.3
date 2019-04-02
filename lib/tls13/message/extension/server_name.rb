# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  using Refinements
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
        attr_reader :extension_type
        attr_reader :server_name

        # @param server_name [String]
        #
        # @raise [TLS13::Error::InternalError]
        #
        # @example
        #   ServerName.new('example.com')
        def initialize(server_name)
          @extension_type = ExtensionType::SERVER_NAME
          @server_name = server_name || ''
          raise Error::InternalError if @server_name.length > 2**16 - 5
        end

        # @return [String]
        def serialize
          return "\x00\x00\x00\x00" if @server_name.empty?

          sn_len = @server_name.length
          binary = ''
          binary += @extension_type
          binary += (sn_len + 5).to_uint16
          binary += (sn_len + 3).to_uint16
          binary += NameType::HOST_NAME
          binary += sn_len.to_uint16
          binary += @server_name
          binary
        end

        # @param binary [String]
        #
        # @raise [TLS13::Error::InternalError]
        #
        # @return [TLS13::Message::Extension::ServerName, UnknownExtension]
        def self.deserialize(binary)
          raise Error::InternalError if binary.nil?

          if binary.length == 1
            return UnknownExtension.new(
              extension_type: ExtensionType::SERVER_NAME,
              extension_data: binary
            )
          end
          return ServerName.new('') if binary.empty?

          deserialize_host_name(binary)
        end

        # @param binary [String]
        #
        # @raise [TLS13::Error::InternalError]
        #
        # @return [TLS13::Message::Extension::ServerName, UnknownExtension]
        def self.deserialize_host_name(binary)
          raise Error::InternalError if binary.nil?

          if binary.length < 5 || binary[2] != NameType::HOST_NAME
            return UnknownExtension.new(
              extension_type: ExtensionType::SERVER_NAME,
              extension_data: binary
            )
          end
          snlist_len = Convert.bin2i(binary.slice(0, 2))
          sn_len = Convert.bin2i(binary.slice(3, 2))
          server_name = binary.slice(5, sn_len)
          if snlist_len + 2 != binary.length || sn_len + 5 != binary.length
            return UnknownExtension.new(
              extension_type: ExtensionType::SERVER_NAME,
              extension_data: binary
            )
          end
          ServerName.new(server_name)
        end
      end
    end
  end
end
