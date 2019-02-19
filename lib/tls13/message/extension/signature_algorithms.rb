module TLS13
  module Message
    module Extension
      module SignatureScheme
        # RSASSA-PKCS1-v1_5 algorithms
        RSA_PKCS1_SHA256       = [0x04, 0x01].freeze
        RSA_PKCS1_SHA384       = [0x05, 0x01].freeze
        RSA_PKCS1_SHA512       = [0x06, 0x01].freeze
        # ECDSA algorithms
        ECDSA_SECP256R1_SHA256 = [0x04, 0x03].freeze
        ECDSA_SECP384R1_SHA384 = [0x05, 0x03].freeze
        ECDSA_SECP521R1_SHA512 = [0x06, 0x03].freeze
        # RSASSA-PSS algorithms with public key OID rsaEncryption
        RSA_PSS_RSAE_SHA256    = [0x08, 0x04].freeze
        RSA_PSS_RSAE_SHA384    = [0x08, 0x05].freeze
        RSA_PSS_RSAE_SHA512    = [0x08, 0x06].freeze
        # EdDSA algorithms
        ED25519                = [0x08, 0x07].freeze
        ED448                  = [0x08, 0x08].freeze
        # RSASSA-PSS algorithms with public key OID RSASSA-PSS
        RSA_PSS_PSS_SHA256     = [0x08, 0x09].freeze
        RSA_PSS_PSS_SHA384     = [0x08, 0x0a].freeze
        RSA_PSS_PSS_SHA512     = [0x08, 0x0b].freeze
        # Legacy algorithms
        RSA_PKCS1_SHA1         = [0x02, 0x01].freeze
        ECDSA_SHA1             = [0x02, 0x03].freeze
        # Reserved Code Points
        # private_use [0xfe, 0x00] ~ [0xff, 0xff]
      end

      class SignatureAlgorithms
        attr_accessor :extension_type
        attr_accessor :length
        attr_accessor :supported_signature_algorithms

        # @param versions [Array of SignatureScheme]
        def initialize(supported_signature_algorithms: [])
          @extension_type = ExtensionType::SIGNATURE_ALGORITHMS
          @supported_signature_algorithms = supported_signature_algorithms || []
          @length = 2 + @supported_signature_algorithms.length * 2
        end

        # @return [Array of Integer]
        def serialize
          binary = []
          binary += @extension_type
          binary += i2uint16(@length)
          binary += i2uint16(supported_signature_algorithms.length * 2)
          binary += @supported_signature_algorithms.flatten
          binary
        end

        # @param binary [Array of Integer]
        #
        # @raise [RuntimeError]
        #
        # @return [TLS13::Message::Extensions::SignatureAlgorithms]
        def self.deserialize(binary)
          raise 'too short binary' if binary.nil? || binary.length < 2

          ssa_len = arr2i([binary[0], binary[1]])
          itr = 2
          supported_signature_algorithms = []
          while itr < ssa_len + 2
            supported_signature_algorithms << [binary[itr], binary[itr + 1]]
            itr += 2
          end
          SignatureAlgorithms.new(
            supported_signature_algorithms: supported_signature_algorithms
          )
        end
      end
    end
  end
end
