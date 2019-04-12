# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  using Refinements
  module Message
    module Extension
      class Cookie
        attr_reader :extension_type
        attr_reader :cookie

        # @param cookie [String]
        #
        # @raise [TLS13::Error::ErrorAlerts]
        def initialize(cookie)
          @extension_type = ExtensionType::COOKIE
          @cookie = cookie || ''
          raise Error::ErrorAlerts, :internal_error \
            if @cookie.length > 2**16 - 3
        end

        # @return [String]
        def serialize
          @extension_type + @cookie.prefix_uint16_length.prefix_uint16_length
        end

        # @param binary [String]
        #
        # @raise [TLS13::Error::ErrorAlerts]
        #
        # @return [TLS13::Message::Extensions::Cookie, nil]
        def self.deserialize(binary)
          raise Error::ErrorAlerts, :internal_error if binary.nil?

          return nil if binary.length < 2

          cookie_len = Convert.bin2i(binary.slice(0, 2))
          cookie = binary.slice(2, cookie_len)
          return nil unless cookie_len + 2 == binary.length &&
                            cookie_len <= 2**16 - 3

          Cookie.new(cookie)
        end
      end
    end
  end
end
