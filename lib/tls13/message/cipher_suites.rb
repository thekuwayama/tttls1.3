# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  module Message
    module CipherSuite
      TLS_AES_128_GCM_SHA256       = "\x13\x01"
      TLS_AES_256_GCM_SHA384       = "\x13\x02"
      TLS_CHACHA20_POLY1305_SHA256 = "\x13\x03"
      TLS_AES_128_CCM_SHA256       = "\x13\x04"
      TLS_AES_128_CCM_8_SHA256     = "\x13\x05"
    end

    DEFALT_CIPHER_SUITES = [CipherSuite::TLS_AES_256_GCM_SHA384,
                            CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
                            CipherSuite::TLS_AES_128_GCM_SHA256].freeze

    class CipherSuites < Array
      alias super_length length

      # @param cipher_suites [Array of CipherSuite]
      #
      # @example
      #   CipherSuites.new([
      #     CipherSuite::TLS_AES_256_GCM_SHA384,
      #     CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
      #     CipherSuite::TLS_AES_128_GCM_SHA256
      #   ])
      def initialize(cipher_suites = DEFALT_CIPHER_SUITES)
        super(cipher_suites)
      end

      # @return [Integer]
      def length
        super_length * 2
      end

      # @return [String]
      def serialize
        uint16_length_prefix(join)
      end

      # @param binary [String]
      #
      # @raise [RuntimeError]
      #
      # @return [TLS13::Message::CipherSuites]
      def self.deserialize(binary)
        raise 'too short binary' if binary.nil?

        cipher_suites = []
        itr = 0
        while itr < binary.length
          cipher_suites << binary.slice(itr, 2)
          itr += 2
        end
        raise 'malformed binary' unless itr == binary.length

        CipherSuites.new(cipher_suites)
      end
    end
  end
end
