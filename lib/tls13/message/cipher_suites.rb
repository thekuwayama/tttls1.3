module TLS13
  module Message
    module CipherSuite
      TLS_AES_128_GCM_SHA256       = [0x13, 0x01].freeze
      TLS_AES_256_GCM_SHA384       = [0x13, 0x02].freeze
      TLS_CHACHA20_POLY1305_SHA256 = [0x13, 0x03].freeze
      TLS_AES_128_CCM_SHA256       = [0x13, 0x04].freeze
      TLS_AES_128_CCM_8_SHA256     = [0x13, 0x05].freeze
    end

    class CipherSuites
      attr_accessor :length
      attr_accessor :cipher_suites

      def initialize(**settings)
        # TODO
      end

      def serialize
        # TODO
      end

      def self.deserialize(binary)
        # TODO
      end
    end
  end
end
