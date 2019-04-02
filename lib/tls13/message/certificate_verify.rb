# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  using Refinements
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
      # @raise [TLS13::Error::InternalError]
      def initialize(signature_scheme:, signature:)
        @msg_type = HandshakeType::CERTIFICATE_VERIFY
        @signature_scheme = signature_scheme
        @signature = signature
        raise Error::InternalError if @signature.length > 2**16 - 1
      end

      # @return [String]
      def serialize
        binary = ''
        binary += @signature_scheme
        binary += @signature.prefix_uint16_length

        @msg_type + binary.prefix_uint24_length
      end

      alias fragment serialize

      # @param binary [String]
      #
      # @raise [TLS13::Error::InternalError, TLSError]
      #
      # @return [TLS13::Message::CertificateVerify]
      def self.deserialize(binary)
        raise Error::InternalError if binary.nil?
        raise Error::TLSError, :decode_error if binary.length < 8
        raise Error::InternalError \
          unless binary[0] == HandshakeType::CERTIFICATE_VERIFY

        msg_len = Convert.bin2i(binary.slice(1, 3))
        signature_scheme = binary.slice(4, 2)
        signature_len = Convert.bin2i(binary.slice(6, 2))
        signature = binary.slice(8, signature_len)
        raise Error::InternalError unless signature_len + 4 == msg_len &&
                                          signature_len + 8 == binary.length

        CertificateVerify.new(signature_scheme: signature_scheme,
                              signature: signature)
      end
    end
  end
end
