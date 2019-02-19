module TLS13
  module Message
    module Extension
      class Cookie
        attr_accessor :extension_type
        attr_accessor :length
        attr_accessor :cookie

        # @param cookie [Array of Integer]
        def initialize(cookie: [])
          @extension_type = ExtensionType::COOKIE
          @cookie = cookie || []
          @length = 2 + @cookie.length
        end

        # @return [Array of Integer]
        def serialize
          binary = []
          binary += @extension_type
          binary += i2uint16(@length)
          binary += i2uint16(@cookie.length)
          binary += @cookie
          binary
        end

        # @param binary [Array of Integer]
        #
        # @raise [RuntimeError]
        #
        # @return [TLS13::Message::Extensions::Cookie]
        def self.deserialize(binary)
          raise 'too short binary' if binary.nil? || binary.length < 2

          cookie_len = arr2i([binary[0], binary[1]])
          cookie = binary.slice(2, cookie_len)
          Cookie.new(cookie: cookie)
        end
      end
    end
  end
end
