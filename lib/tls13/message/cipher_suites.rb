module TLS13
  module Message
    module CipherSuite
      TLS_AES_128_GCM_SHA256       = "\x13\x01".freeze
      TLS_AES_256_GCM_SHA384       = "\x13\x02".freeze
      TLS_CHACHA20_POLY1305_SHA256 = "\x13\x03".freeze
      TLS_AES_128_CCM_SHA256       = "\x13\x04".freeze
      TLS_AES_128_CCM_8_SHA256     = "\x13\x05".freeze
    end

    DEFALT_CIPHER_SUITES = [CipherSuite::TLS_AES_256_GCM_SHA384,
                            CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
                            CipherSuite::TLS_AES_128_GCM_SHA256].freeze

    class CipherSuites
      attr_accessor :length
      attr_accessor :cipher_suites

      # @param cipher_suites [Array of CipherSuite]
      def initialize(cipher_suites = DEFALT_CIPHER_SUITES)
        @cipher_suites = cipher_suites || []
        @length = @cipher_suites.length * 2
      end

      # @return [String]
      def serialize
        binary = ''
        binary += i2uint16(@length)
        binary += @cipher_suites.join
        binary
      end

      # @param binary [String]
      #
      # @raise [RuntimeError]
      #
      # @return [TLS13::Message::CipherSuites]
      def self.deserialize(binary)
        raise 'too short binary' if binary.nil? || binary.length < 2

        cs_len = bin2i(binary.slice(0, 2))
        raise 'malformed binary' unless binary.length == cs_len + 2

        cipher_suites = []
        itr = 2
        while itr < cs_len + 2
          cipher_suites << binary.slice(itr, 2)
          itr += 2
        end
        CipherSuites.new(cipher_suites)
      end
    end
  end
end
