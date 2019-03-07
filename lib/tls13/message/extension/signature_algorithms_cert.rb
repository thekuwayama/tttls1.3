# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
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
        # @return [TLS13::Message::Extensions::SignatureAlgorithmsCert]
        def self.deserialize(binary)
          extension = SignatureAlgorithms.deserialize(binary)
          extension.extension_type = ExtensionType::SIGNATURE_ALGORITHMS_CERT
          extension
        end
      end
    end
  end
end
