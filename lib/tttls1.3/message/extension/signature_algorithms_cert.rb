# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  module Message
    module Extension
      class SignatureAlgorithmsCert < SignatureAlgorithms
        # @param versions [Array of SignatureScheme]
        def initialize(supported_signature_algorithms)
          super(supported_signature_algorithms)
          @extension_type = ExtensionType::SIGNATURE_ALGORITHMS_CERT
        end

        # @param binary [String]
        #
        # @return [TTTLS13::Message::Extensions::SignatureAlgorithmsCert]
        def self.deserialize(binary)
          extension = SignatureAlgorithms.deserialize(binary)
          SignatureAlgorithmsCert.new(extension.supported_signature_algorithms)
        end
      end
    end
  end
end
