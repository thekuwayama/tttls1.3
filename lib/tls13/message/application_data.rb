# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  module Message
    class ApplicationData
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
      # @return [TLS13::Message::ApplicationData]
      def self.deserialize(binary)
        ApplicationData.new(binary || '')
      end
    end
  end
end
