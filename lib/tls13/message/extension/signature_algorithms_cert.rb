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
        # @raise [RuntimeError]
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
