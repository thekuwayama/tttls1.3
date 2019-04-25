# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
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
    # ED25519                = "\x08\x07" # UNSUPPORTED
    # ED448                  = "\x08\x08" # UNSUPPORTED
    # RSASSA-PSS algorithms with public key OID RSASSA-PSS
    RSA_PSS_PSS_SHA256     = "\x08\x09"
    RSA_PSS_PSS_SHA384     = "\x08\x0a"
    RSA_PSS_PSS_SHA512     = "\x08\x0b"
    # Legacy algorithms
    # RSA_PKCS1_SHA1         = "\x02\x01" # UNSUPPORTED
    # ECDSA_SHA1             = "\x02\x03" # UNSUPPORTED
    # Reserved Code Points
    # private_use "\xfe\x00" ~ "\xff\xff"
  end
end
