# encoding: ascii-8bit
# frozen_string_literal: true

require 'openssl'

module TLS13
  module Message
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

    class CertificateVerify
      attr_reader :msg_type
      attr_reader :signature_scheme
      attr_reader :signature

      # @param signature_scheme [TLS13::Message::SignatureScheme]
      # @param signature [String]
      #
      # @raise [RuntimeError]
      def initialize(signature_scheme:, signature:)
        @msg_type = HandshakeType::CERTIFICATE_VERIFY
        @signature_scheme = signature_scheme
        @signature = signature
        raise 'invalid signature' if @signature.length > 2**16 - 1

        # TODO: check @signature.length using type of SignatureScheme
      end

      # @return [String]
      def serialize
        binary = ''
        binary += @signature_scheme
        binary += uint16_length_prefix(@signature)

        @msg_type + uint24_length_prefix(binary)
      end

      alias fragment serialize

      # @param binary [String]
      #
      # @raise [RuntimeError]
      #
      # @return [TLS13::Message::CertificateVerify]
      def self.deserialize(binary)
        raise 'invalid HandshakeType' \
          unless binary[0] == HandshakeType::CERTIFICATE_VERIFY

        msg_len = bin2i(binary.slice(1, 3))
        signature_scheme = binary.slice(4, 2)
        signature_len = bin2i(binary.slice(6, 2))
        signature = binary.slice(8, signature_len)
        raise 'malformed binary' \
          unless binary.length == signature_len + 8 &&
                 signature_len + 4 == msg_len

        CertificateVerify.new(signature_scheme: signature_scheme,
                              signature: signature)
      end
    end
  end
end
