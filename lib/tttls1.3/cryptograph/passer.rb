# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  module Cryptograph
    class Passer
      # @param content [String]
      #
      # @return [String]
      def encrypt(content, _type)
        content
      end

      # @param encrypted_record [String]
      #
      # @return [String and TTTLS13::Message::ContentType]
      def decrypt(encrypted_record, _auth_data)
        [encrypted_record, encrypted_record[0]]
      end
    end
  end
end
