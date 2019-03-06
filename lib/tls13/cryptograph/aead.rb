# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  module Cryptograph
    class Aead
      # @param type [TLS13::Message::ContentType] TLSInnerPlaintext.type
      # @param length_of_padding [Integer]
      # @param nonce [String]
      # @param key [String]
      # @cipher_suite [TLS13::Message::CipherSuite]
      def initialize(type: ContentType::INVALID,
                     length_of_padding: 0,
                     nonce: nil,
                     key: nil,
                     cipher_suite: nil)
        @type = type
        @length_of_padding = length_of_padding
        case cipher_suite
        when CipherSuite::TLS_AES_128_GCM_SHA256
          @cipher = OpenSSL::Cipher::AES128.new(:GCM)
        when CipherSuite::TLS_AES_256_GCM_SHA384
          @cipher = OpenSSL::Cipher::AES256.new(:GCM)
        when CipherSuite::TLS_AES_128_CCM_SHA256
          @cipher = OpenSSL::Cipher::AES128.new(:CCM)
        when CipherSuite::TLS_AES_128_CCM_8_SHA256
          @cipher = OpenSSL::Cipher::AES128.new(:CCM)
        else
          # CipherSuite::TLS_CHACHA20_POLY1305_SHA256
          raise 'unsupported CipherSuite'
        end
        @cipher.key = key
        @cipher.iv = nonce
      end

      # @return [String]
      def additional_data(plaintext_len)
       # length of auth_tag = 16
        ciphertext_len = plaintext_len + 16
        ContentType::APPLICATION_DATA \
        + ProtocolVersion::TLS_1_2 \
        + i2uint16(ciphertext_len)
      end

      # AEAD-Encrypt(write_key, nonce, additional_data, plaintext)
      #
      # @param content [String]
      #
      # @return [String]
      def encrypt(content)
        cipher = @cipher.encrypt
        plaintext = content + @type + "\x00" * @length_of_padding
        cipher.auth_data = additional_data(plaintext.length)

        encrypted_data = cipher.update(plaintext) + cipher.final
        encrypted_data + cipher.auth_tag
      end

      # AEAD-Decrypt(peer_write_key, nonce,
      #              additional_data, AEADEncrypted)
      #
      # @param encrypted_record [String]
      # @param auth_data [String]
      #
      # @raise [OpenSSL::Cipher::CipherError]
      #
      # @return [String]
      def decrypt(encrypted_record, auth_data)
        decipher = @cipher.decrypt
        er_len = encrypted_record.length
        auth_tag = encrypted_record.slice(er_len - 16, 16)
        decipher.auth_tag = auth_tag
        decipher.auth_data = auth_data # record header of TLSCiphertext

        decipher.update(encrypted_record)[0...-17]
      end
    end
  end
end
