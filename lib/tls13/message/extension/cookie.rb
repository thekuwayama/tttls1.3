# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  module Message
    module Extension
      class Cookie
        attr_reader   :extension_type
        attr_accessor :length
        attr_accessor :cookie

        # @param cookie [String]
        def initialize(cookie)
          @extension_type = ExtensionType::COOKIE
          @cookie = cookie || ''
          @length = 2 + @cookie.length
        end

        # @return [String]
        def serialize
          binary = ''
          binary += @extension_type
          binary += i2uint16(@length)
          binary += i2uint16(@cookie.length)
          binary += @cookie
          binary
        end

        # @param binary [String]
        #
        # @raise [RuntimeError]
        #
        # @return [TLS13::Message::Extensions::Cookie]
        def self.deserialize(binary)
          raise 'too short binary' if binary.nil? || binary.length < 2

          cookie_len = bin2i(binary.slice(0, 2))
          raise 'malformed binary' unless binary.length == cookie_len + 2

          cookie = binary.slice(2, cookie_len)
          Cookie.new(cookie)
        end
      end
    end
  end
end
