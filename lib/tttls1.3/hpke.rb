# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  # NOTE: Hpke module is the adapter for ech_config to use hpke-rb.
  module Hpke
    def self.kem_id2dhkem(kem_id)
      # https://www.iana.org/assignments/hpke/hpke.xhtml#hpke-kem-ids
      case kem_id
      when 0x0010
        %i[p_256 sha256]
      when 0x0011
        %i[p_384 sha384]
      when 0x0012
        %i[p_521 sha512]
      when 0x0020
        %i[x25519 sha256]
      when 0x0021
        %i[x448 sha512]
      end
    end

    module KdfId
      # https://www.iana.org/assignments/hpke/hpke.xhtml#hpke-kdf-ids
      HKDF_SHA256 = 0x0001
      HKDF_SHA384 = 0x0002
      HKDF_SHA512 = 0x0003
    end

    def self.kdf_id2kdf_hash(kdf_id)
      case kdf_id
      when KdfId::HKDF_SHA256
        :sha256
      when KdfId::HKDF_SHA384
        :sha384
      when KdfId::HKDF_SHA512
        :sha512
      end
    end

    module AeadId
      # https://www.iana.org/assignments/hpke/hpke.xhtml#hpke-aead-ids
      AES_128_GCM       = 0x0001
      AES_256_GCM       = 0x0002
      CHACHA20_POLY1305 = 0x0003
    end

    def self.aead_id2overhead_len(aead_id)
      case aead_id
      when AeadId::AES_128_GCM, AeadId::CHACHA20_POLY1305
        16
      when AeadId::AES_256_GCM
        32
      end
    end

    def self.aead_id2aead_cipher(aead_id)
      case aead_id
      when AeadId::AES_128_GCM
        :aes_128_gcm
      when AeadId::AES_256_GCM
        :aes_256_gcm
      when AeadId::CHACHA20_POLY1305
        :chacha20_poly1305
      end
    end
  end
end
