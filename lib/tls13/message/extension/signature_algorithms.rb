# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  using Refinements
  module Message
    module Extension
      class SignatureAlgorithms
        attr_accessor :extension_type # for signature_algorithms_cert
        attr_reader   :supported_signature_algorithms

        # @param supported_signature_algorithms [Array of SignatureScheme]
        def initialize(supported_signature_algorithms)
          @extension_type = ExtensionType::SIGNATURE_ALGORITHMS
          @supported_signature_algorithms = supported_signature_algorithms || []
          raise 'invalid supported_signature_algorithms' \
            if @supported_signature_algorithms.empty? ||
               @supported_signature_algorithms.length * 2 > 2**16 - 3
        end

        # @return [String]
        def serialize
          binary = ''
          binary += (@supported_signature_algorithms.length * 2).to_uint16
          binary += @supported_signature_algorithms.join

          @extension_type + binary.prefix_uint16_length
        end

        # @param binary [String]
        #
        # @raise [RuntimeError]
        #
        # @return [TLS13::Message::Extensions::SignatureAlgorithms]
        def self.deserialize(binary)
          raise 'too short binary' if binary.nil? || binary.length < 2

          ssa_len = Convert.bin2i(binary.slice(0, 2))
          raise 'malformed binary' unless binary.length == ssa_len + 2

          i = 2
          supported_signature_algorithms = []
          while i < ssa_len + 2
            supported_signature_algorithms << binary.slice(i, 2)
            i += 2
          end
          SignatureAlgorithms.new(supported_signature_algorithms)
        end
      end
    end
  end
end
