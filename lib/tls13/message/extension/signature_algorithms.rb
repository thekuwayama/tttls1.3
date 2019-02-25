# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  module Message
    module Extension
      module SignatureScheme
        # RSASSA-PKCS1-v1_5 algorithms
        RSA_PKCS1_SHA256       = "\x04\x01"
        RSA_PKCS1_SHA384       = "\x05\x01"
        RSA_PKCS1_SHA512       = "\x06\x01"
        # ECDSA algorithms
        ECDSA_SECP256R1_SHA256 = "\x04\x03"
        ECDSA_SECP384R1_SHA384 = "\x05\x03"
        ECDSA_SECP521R1_SHA512 = "\x06\x03"
        # RSASSA-PSS algorithms with public key OID rsaEncryption
        RSA_PSS_RSAE_SHA256    = "\x08\x04"
        RSA_PSS_RSAE_SHA384    = "\x08\x05"
        RSA_PSS_RSAE_SHA512    = "\x08\x06"
        # EdDSA algorithms
        ED25519                = "\x08\x07"
        ED448                  = "\x08\x08"
        # RSASSA-PSS algorithms with public key OID RSASSA-PSS
        RSA_PSS_PSS_SHA256     = "\x08\x09"
        RSA_PSS_PSS_SHA384     = "\x08\x0a"
        RSA_PSS_PSS_SHA512     = "\x08\x0b"
        # Legacy algorithms
        RSA_PKCS1_SHA1         = "\x02\x01"
        ECDSA_SHA1             = "\x02\x03"
        # Reserved Code Points
        # private_use "\xfe\x00" ~ "\xff\xff"
      end

      class SignatureAlgorithms
        attr_accessor :extension_type # for signature_algorithms_cert
        attr_accessor :length
        attr_accessor :supported_signature_algorithms

        # @param supported_signature_algorithms [Array of SignatureScheme]
        def initialize(supported_signature_algorithms)
          @extension_type = ExtensionType::SIGNATURE_ALGORITHMS
          @supported_signature_algorithms = supported_signature_algorithms || []
          @length = 2 + @supported_signature_algorithms.length * 2
        end

        # @return [String]
        def serialize
          binary = ''
          binary += @extension_type
          binary += i2uint16(@length)
          binary += i2uint16(supported_signature_algorithms.length * 2)
          binary += @supported_signature_algorithms.join
          binary
        end

        # @param binary [String]
        #
        # @raise [RuntimeError]
        #
        # @return [TLS13::Message::Extensions::SignatureAlgorithms]
        def self.deserialize(binary)
          raise 'too short binary' if binary.nil? || binary.length < 2

          ssa_len = bin2i(binary.slice(0, 2))
          raise 'malformed binary' unless binary.length == ssa_len + 2

          itr = 2
          supported_signature_algorithms = []
          while itr < ssa_len + 2
            supported_signature_algorithms << binary.slice(itr, 2)
            itr += 2
          end
          SignatureAlgorithms.new(supported_signature_algorithms)
        end
      end
    end
  end
end
