# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  using Refinements
  module Message
    class CompressedCertificate
      attr_reader :msg_type
      attr_reader :certificate_message
      attr_reader :algorithm

      # @param ct [TTTLS13::Message::Certificate]
      # @param algorithm [CertificateCompressionAlgorithm]
      def initialize(certificate_message:, algorithm:)
        @msg_type = HandshakeType::COMPRESSED_CERTIFICATE
        @ccertificate_message = certificate_message
        @algorithm = algorithm
      end

      # @return [String]
      def serialize
        binary = ''
        binary += @algorithm
        binary += compress_ct.prefix_uint24_length

        @msg_type + binary.prefix_uint24_length
      end

      class << self
        def compress_ct
          binary = @certificate_message.serialize

          case @algorithm
          when Extension::CertificateCompressionAlgorithm::ZLIB
            Zlib::Deflate.deflate(binary)
          else # TODO: BROTLI, ZSTD
            raise Error::ErrorAlerts, :internal_error
          end
        end
      end

      # @param binary [String]
      #
      # @raise [TTTLS13::Error::ErrorAlerts]
      #
      # @return [TTTLS13::Message::CompressedCertificate]
      def self.deserialize(binary)
        raise Error::ErrorAlerts, :internal_error if binary.nil?
        raise Error::ErrorAlerts, :decode_error if binary.length < 5

        algorithm = binary.slice(0, 2)
        uncompressed_length = Convert.bin2i(binary.slice(2, 5))
        case algorithm
        when Extension::CertificateCompressionAlgorithm::ZLIB
          ct_bin = Zlib::Inflate.inflate(binary.slice(5, binary.length - 5))
        else # TODO: BROTLI, ZSTD
          raise Error::ErrorAlerts, :bad_certificate
        end

        raise Error::ErrorAlerts, :bad_certificate \
          if ct_bin.length != uncompressed_length

        certificate_message = Certificate.deserialize(ct_bin)
        CompressedCertificate.new(certificate_message: certificate_message,
                                  algorithm: algorithm)
      end
    end
  end
end
