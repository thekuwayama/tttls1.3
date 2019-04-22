# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  module Message
    class ApplicationData
      attr_reader :fragment

      # @param [String]
      def initialize(fragment)
        @fragment = fragment
      end

      # @return [String]
      def serialize
        @fragment
      end

      # @param binary [String]
      #
      # @return [TTTLS13::Message::ApplicationData]
      def self.deserialize(binary)
        ApplicationData.new(binary || '')
      end
    end
  end
end
