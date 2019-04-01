# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  using Refinements
  module Cryptograph
    class Aead
      # @param cipher_suite [TLS13::CipherSuite]
      # @param write_key [String]
      # @param write_iv [String]
      # @param sequence_number [String] uint64
      # @param type [TLS13::Message::ContentType] TLSInnerPlaintext.type
      # @param length_of_padding [Integer]
      def initialize(cipher_suite:, write_key:, write_iv:,
                     sequence_number:, length_of_padding: 0)
        @cipher_suite = cipher_suite
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
          # TODO: CipherSuite::TLS_CHACHA20_POLY1305_SHA256
          raise Error::InternalError
        end
        @write_key = write_key
        @write_iv = write_iv
        @sequence_number = sequence_number
        @length_of_padding = length_of_padding
      end

      # AEAD-Encrypt(write_key, nonce, additional_data, plaintext)
      #
      # @param content [String]
      # @param type [TLS13::Message::ContentType]
      #
      # @return [String]
      def encrypt(content, type)
        reset_cipher
        cipher = @cipher.encrypt
        plaintext = content + type + "\x00" * @length_of_padding
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
      # @return [String and TLS13::Message::ContentType]
      def decrypt(encrypted_record, auth_data)
        reset_cipher
        decipher = @cipher.decrypt
        auth_tag = encrypted_record[-16..-1]
        decipher.auth_tag = auth_tag
        decipher.auth_data = auth_data # record header of TLSCiphertext
        clear = decipher.update(encrypted_record[0...-16]) # auth_tag
        decipher.final
        zeros_len = scan_zeros(clear)
        postfix_len = 1 + zeros_len # type || zeros
        [clear[0...-postfix_len], clear[-postfix_len]]
      end

      private

      # @return [String]
      def additional_data(plaintext_len)
        ciphertext_len = plaintext_len + 16 # length of auth_tag is 16
        Message::ContentType::APPLICATION_DATA \
        + Message::ProtocolVersion::TLS_1_2 \
        + ciphertext_len.to_uint16
      end

      def reset_cipher
        @cipher.reset
        @cipher.key = @write_key
        iv_len = CipherSuite.iv_len(@cipher_suite)
        @cipher.iv = @sequence_number.xor(@write_iv, iv_len)
      end

      # @param [String]
      #
      # @return [Integer]
      def scan_zeros(clear)
        i = 0
        i += 1 while clear[-i] == "\x00"
        i
      end
    end
  end
end
