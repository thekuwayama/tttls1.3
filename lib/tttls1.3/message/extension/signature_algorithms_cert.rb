# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  module Message
    module Extension
      class SignatureAlgorithmsCert < SignatureAlgorithms
        # @param supported_signature_algorithms [Array] Array of SignatureScheme
        def initialize(supported_signature_algorithms)
          super(supported_signature_algorithms)
          @extension_type = ExtensionType::SIGNATURE_ALGORITHMS_CERT
        end

        # @param binary [String]
        #
        # @return [TTTLS13::Message::Extensions::SignatureAlgorithmsCert, nil]
        def self.deserialize(binary)
          ssa = deserialize_supported_signature_algorithms(binary)
          return nil if ssa.nil?

          SignatureAlgorithmsCert.new(ssa)
        end
      end
    end
  end
end
