module TLS13
  module Message
    module CipherSuite
      TLS_AES_128_GCM_SHA256       = [0x13, 0x01].freeze
      TLS_AES_256_GCM_SHA384       = [0x13, 0x02].freeze
      TLS_CHACHA20_POLY1305_SHA256 = [0x13, 0x03].freeze
      TLS_AES_128_CCM_SHA256       = [0x13, 0x04].freeze
      TLS_AES_128_CCM_8_SHA256     = [0x13, 0x05].freeze
    end

    DEFALT_CIPHER_SUITES = [CipherSuite::TLS_AES_256_GCM_SHA384,
                            CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
                            CipherSuite::TLS_AES_128_GCM_SHA256].freeze

    class CipherSuites
      attr_accessor :length
      attr_accessor :cipher_suites

      def initialize(cipher_suites: DEFALT_CIPHER_SUITES)
        @cipher_suites = cipher_suites
        @length = 0
        @length = @cipher_suites.length * 2 unless @cipher_suites.nil?
      end

      def serialize
        binary = []
        binary += i2uint16(@length)
        binary += @cipher_suites
        binary
      end

      # @param binary [Array of Integer]
      def self.deserialize(binary)
        raise 'too short binary' if binary.nil? || binary.length < 2

        length = arr2i([binary[0], binary[1]])
        raise 'malformed binary' unless binary.length == length + 2

        cipher_suites = binary[2..-1].each_slice(2).to_a
        CipherSuites.new(cipher_suites: cipher_suites)
      end
    end
  end
end
