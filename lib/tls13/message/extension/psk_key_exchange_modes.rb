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
        # @raise [RuntimeError]
        #
        # @return [TLS13::Message::Extensions::PskKeyExchangeModes]
        def self.deserialize(binary)
          raise 'too short binary' if binary.nil? || binary.empty?

          kem_len = Convert.bin2i(binary[0])
          raise 'malformed binary' unless binary.length == kem_len + 1

          ke_modes = []
          itr = 1
          while itr < kem_len + 1
            ke_modes << binary[itr]
            itr += 1
          end
          PskKeyExchangeModes.new(ke_modes)
        end
      end
    end
  end
end
