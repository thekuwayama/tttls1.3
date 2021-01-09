# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  using Refinements
  module Message
    module Extension
      module CertificateCompressionAlgorithm
        ZLIB   = "\x00\x01"
        BROTLI = "\x00\x02"
        ZSTD   = "\x00\x03"
      end

      # https://tools.ietf.org/html/rfc8879
      class CompressCertificate
        attr_reader :extension_type
        attr_reader :algorithms

        # @param algorithms [Array of String]
        #
        # @raise [TTTLS13::Error::ErrorAlerts]
        #
        # @example
        #   CompressCertificate([CertificateCompressionAlgorithm::ZLIB])
        def initialize(algorithms)
          @extension_type = ExtensionType::COMPRESS_CERTIFICATE
          @algorithms = algorithms || []
          raise Error::ErrorAlerts, :internal_error \
            if @algorithms.join.length < 2 ||
               @algorithms.join.length > 2**8 - 2
        end

        # @return [String]
        def serialize
          binary = @algorithms.join.prefix_uint8_length

          @extension_type + binary.prefix_uint16_length
        end

        # @param binary [String]
        #
        # @raise [TTTLS13::Error::ErrorAlerts]
        #
        # @return [TTTLS13::Message::Extension::CompressCertificate, nil]
        def self.deserialize(binary)
          raise Error::ErrorAlerts, :internal_error if binary.nil?

          return nil if binary.length < 3

          al_len = Convert.bin2i(binary.slice(0, 1))
          return nil if binary.length != al_len + 1

          CompressCertificate.new(binary.slice(1, al_len + 1).scan(/.{2}/m))
        end
      end
    end
  end
end
