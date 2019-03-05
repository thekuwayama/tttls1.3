# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  module Cryptograph
    class Passer
      # @param content [String]
      #
      # @return [String]
      def encrypt(content)
        content
      end

      # @param encrypted_record [String]
      #
      # @return [String]
      def decrypt(encrypted_record)
        encrypted_record
      end
    end
  end
end
