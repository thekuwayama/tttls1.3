# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  using Refinements
  module Message
    module Extension
      module PskKeyExchangeMode
        PSK_KE     = "\x00"
        PSK_DHE_KE = "\x01"
      end

      class PskKeyExchangeModes
        attr_reader :extension_type
        attr_reader :ke_modes

        # @param ke_modes [Array of PskKeyExchangeMode]
        def initialize(ke_modes = [])
          @extension_type = ExtensionType::PSK_KEY_EXCHANGE_MODES
          @ke_modes = ke_modes || []
        end

        # @return [String]
        def serialize
          binary = @ke_modes.join.prefix_uint8_length

          @extension_type + binary.prefix_uint16_length
        end

        # @param binary [String]
        #
        # @raise [TLS13::Error::InternalError]
        #
        # @return [TLS13::Message::Extensions::PskKeyExchangeModes,
        #          UknownExtension]
        def self.deserialize(binary)
          raise Error::InternalError if binary.nil?

          if binary.empty?
            return UknownExtension.new(
              extension_type: ExtensionType::PSK_KEY_EXCHANGE_MODES,
              extension_data: binary
            )
          end
          kem_len = Convert.bin2i(binary[0])
          if kem_len + 1 != binary.length
            return UknownExtension.new(
              extension_type: ExtensionType::PSK_KEY_EXCHANGE_MODES,
              extension_data: binary
            )
          end
          ke_modes = []
          i = 1
          while i < kem_len + 1
            ke_modes << binary[i]
            i += 1
          end
          PskKeyExchangeModes.new(ke_modes)
        end
      end
    end
  end
end
