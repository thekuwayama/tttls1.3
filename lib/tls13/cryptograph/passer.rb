module TLS13
  module Cryptograph
    class Passer
      # @param plaintext [String]
      #
      # @return [String]
      def encrypt(plaintext)
        plaintext
      end

      # @param ciphertext [String]
      #
      # @return [String]
      def decrypt(ciphertext)
        ciphertext
      end
    end
  end
end
