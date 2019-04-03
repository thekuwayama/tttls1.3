# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  using Refinements
  module CipherSuite
    TLS_AES_128_GCM_SHA256       = "\x13\x01"
    TLS_AES_256_GCM_SHA384       = "\x13\x02"
    TLS_CHACHA20_POLY1305_SHA256 = "\x13\x03"
    TLS_AES_128_CCM_SHA256       = "\x13\x04"
    TLS_AES_128_CCM_8_SHA256     = "\x13\x05"

    class << self
      def digest(cipher_suite)
        case cipher_suite
        when TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256,
             TLS_AES_128_CCM_SHA256, TLS_AES_128_CCM_SHA256,
             TLS_AES_128_CCM_8_SHA256
          'SHA256'
        when TLS_AES_256_GCM_SHA384
          'SHA384'
        else
          raise Error::TLSError, :internal_error
        end
      end

      def hash_len(cipher_suite)
        case cipher_suite
        when TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256,
             TLS_AES_128_CCM_SHA256, TLS_AES_128_CCM_SHA256,
             TLS_AES_128_CCM_8_SHA256
          32
        when TLS_AES_256_GCM_SHA384
          48
        else
          raise Error::TLSError, :internal_error
        end
      end

      def key_len(cipher_suite)
        case cipher_suite
        when TLS_AES_128_GCM_SHA256, TLS_AES_128_CCM_SHA256,
             TLS_AES_128_CCM_SHA256, TLS_AES_128_CCM_8_SHA256
          16
        when TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
          32
        else
          raise Error::TLSError, :internal_error
        end
      end

      def iv_len(cipher_suite)
        case cipher_suite
        when TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
             TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_CCM_SHA256,
             TLS_AES_128_CCM_8_SHA256
          12
        else
          raise Error::TLSError, :internal_error
        end
      end
    end
  end

  DEFALT_CIPHER_SUITES = [CipherSuite::TLS_AES_256_GCM_SHA384,
                          CipherSuite::TLS_AES_128_GCM_SHA256].freeze

  class CipherSuites < Array
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

    # @return [String]
    def serialize
      join.prefix_uint16_length
    end

    # @param binary [String]
    #
    # @raise [RuntimeError]
    #
    # @return [TLS13::CipherSuites]
    def self.deserialize(binary)
      raise 'too short binary' if binary.nil?

      cipher_suites = []
      i = 0
      while i < binary.length
        cipher_suites << binary.slice(i, 2)
        i += 2
      end
      raise 'malformed binary' unless i == binary.length

      CipherSuites.new(cipher_suites)
    end
  end
end
