# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  using Refinements
  module Cryptograph
    class Aead
      attr_reader :auth_tag_len

      # @param cipher_suite [TTTLS13::CipherSuite]
      # @param write_key [String]
      # @param write_iv [String]
      # @param sequence_number [String] uint64
      # @param length_of_padding [Integer]
      def initialize(cipher_suite:, write_key:, write_iv:,
                     sequence_number:, length_of_padding: 0)
        @cipher_suite = cipher_suite
        case cipher_suite
        when CipherSuite::TLS_AES_128_GCM_SHA256
          @cipher = OpenSSL::Cipher.new('aes-128-gcm')
        when CipherSuite::TLS_AES_256_GCM_SHA384
          @cipher = OpenSSL::Cipher.new('aes-256-gcm')
        when CipherSuite::TLS_CHACHA20_POLY1305_SHA256
          @cipher = OpenSSL::Cipher.new('chacha20-poly1305')
        when CipherSuite::TLS_AES_128_CCM_SHA256
          @cipher = OpenSSL::Cipher.new('aes-128-ccm')
          # CipherSuite::TLS_AES_128_CCM_8_SHA256
        else
          raise Error::ErrorAlerts, :internal_error
        end
        @write_key = write_key
        @write_iv = write_iv
        @sequence_number = sequence_number
        @length_of_padding = length_of_padding
        @auth_tag_len = CipherSuite.auth_tag_len(@cipher_suite)
      end

      #     AEAD-Encrypt(write_key, nonce, additional_data, plaintext)
      #
      # @param content [String]
      # @param type [TTTLS13::Message::ContentType]
      #
      # @return [String]
      def encrypt(content, type)
        cipher = reset_cipher
        plain_text = content + type + @length_of_padding.zeros
        cipher.ccm_data_len = plain_text.length \
          if CipherSuite.ccm?(@cipher_suite)
        cipher.auth_data = additional_data(plain_text.length)
        cipher_text = cipher.update(plain_text) + cipher.final
        @sequence_number.succ

        cipher_text + cipher.auth_tag
      end

      #     AEAD-Decrypt(peer_write_key, nonce,
      #                  additional_data, AEADEncrypted)
      #
      # @param encrypted_record [String]
      # @param auth_data [String]
      #
      # @raise [OpenSSL::Cipher::CipherError]
      #
      # @return [String]
      # @return [TTTLS13::Message::ContentType]
      def decrypt(encrypted_record, auth_data)
        decipher = reset_decipher
        cipher_text = encrypted_record[0...-@auth_tag_len]
        decipher.ccm_data_len = cipher_text.length \
          if CipherSuite.ccm?(@cipher_suite)
        auth_tag = encrypted_record[-@auth_tag_len..]
        decipher.auth_tag = auth_tag
        decipher.auth_data = auth_data # record header of TLSCiphertext
        plain_text = decipher.update(cipher_text)
        decipher.final
        zeros_len = scan_zeros(plain_text)
        postfix_len = 1 + zeros_len # type || zeros
        @sequence_number.succ

        [plain_text[0...-postfix_len], plain_text[-postfix_len]]
      end

      #     struct {
      #         opaque content[TLSPlaintext.length];
      #         ContentType type;
      #         uint8 zeros[length_of_padding];
      #     } TLSInnerPlaintext;
      #
      # @param record_size_limit [Integer]
      #
      # @return [Integer]
      def tlsplaintext_length_limit(record_size_limit)
        record_size_limit - 1 - @length_of_padding
      end

      private

      # @return [String]
      def additional_data(plaintext_len)
        ciphertext_len = plaintext_len + @auth_tag_len

        Message::ContentType::APPLICATION_DATA \
        + Message::ProtocolVersion::TLS_1_2 \
        + ciphertext_len.to_uint16
      end

      # @return [OpenSSL::Cipher]
      def reset_cipher
        cipher = @cipher.encrypt
        cipher.reset
        cipher.auth_tag_len = @auth_tag_len \
          if CipherSuite.ccm?(@cipher_suite)
        cipher.iv_len = CipherSuite.iv_len(@cipher_suite)
        cipher.key = @write_key
        cipher.iv = @sequence_number.xor(@write_iv, cipher.iv_len)

        cipher
      end

      # @return [OpenSSL::Cipher]
      def reset_decipher
        decipher = @cipher.decrypt
        decipher.reset
        decipher.auth_tag_len = @auth_tag_len \
          if CipherSuite.ccm?(@cipher_suite)
        decipher.iv_len = CipherSuite.iv_len(@cipher_suite)
        decipher.key = @write_key
        decipher.iv = @sequence_number.xor(@write_iv, decipher.iv_len)

        decipher
      end

      # @param clear [String]
      #
      # @return [Integer]
      def scan_zeros(clear)
        i = 1
        i += 1 while clear[-i] == "\x00"
        i - 1
      end
    end
  end
end
