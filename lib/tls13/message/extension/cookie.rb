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
        # @raise [TLS13::Error::InternalError]
        def initialize(cookie)
          @extension_type = ExtensionType::COOKIE
          @cookie = cookie || ''
          raise Error::InternalError if @cookie.length > 2**16 - 3
        end

        # @return [String]
        def serialize
          @extension_type + @cookie.prefix_uint16_length.prefix_uint16_length
        end

        # @param binary [String]
        #
        # @raise [TLS13::Error::InternalError]
        #
        # @return [TLS13::Message::Extensions::Cookie, UnknownExtension]
        def self.deserialize(binary)
          raise Error::InternalError if binary.nil?

          if binary.length < 2
            return UnknownExtension.new(extension_type: ExtensionType::COOKIE,
                                        extension_data: binary)
          end
          cookie_len = Convert.bin2i(binary.slice(0, 2))
          cookie = binary.slice(2, cookie_len)
          if cookie_len + 2 != binary.length || cookie_len > 2**16 - 3
            return UnknownExtension.new(extension_type: ExtensionType::COOKIE,
                                        extension_data: binary)
          end
          Cookie.new(cookie)
        end
      end
    end
  end
end
