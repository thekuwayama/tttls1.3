# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  using Refinements
  module Message
    module Extension
      class Alpn
        attr_reader :extension_type, :protocol_name_list

        # @param protocol_name_list [Array] Array of String
        #
        # @raise [TTTLS13::Error::ErrorAlerts]
        #
        # @example
        #     Alpn.new(['h2', 'http/1.1'])
        #
        # https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
        def initialize(protocol_name_list)
          @extension_type \
            = ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION
          @protocol_name_list = protocol_name_list || []
          raise Error::ErrorAlerts, :internal_error \
            if @protocol_name_list.empty?
        end

        # @return [String]
        def serialize
          binary = @protocol_name_list.map(&:prefix_uint8_length)
                                      .join
                                      .prefix_uint16_length

          @extension_type + binary.prefix_uint16_length
        end

        # @param binary [String]
        #
        # @raise [TTTLS13::Error::ErrorAlerts]
        #
        # @return [TTTLS13::Message::Extension::Alpn, nil]
        def self.deserialize(binary)
          raise Error::ErrorAlerts, :internal_error if binary.nil?

          return nil if binary.length < 2

          pnlist_len = Convert.bin2i(binary.slice(0, 2))
          i = 2
          protocol_name_list = []
          while i < pnlist_len + 2
            return nil if i + 1 > binary.length

            pn_len = Convert.bin2i(binary.slice(i, 1))
            i += 1
            return nil if i + pn_len > binary.length

            protocol_name_list << binary.slice(i, pn_len)
            i += pn_len
          end
          return nil unless i == binary.length &&
                            pnlist_len + 2 == binary.length

          Alpn.new(protocol_name_list)
        end
      end
    end
  end
end
