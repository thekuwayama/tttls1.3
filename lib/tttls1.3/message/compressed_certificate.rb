# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  using Refinements
  module Message
    class CompressedCertificate
      attr_reader :msg_type
      attr_reader :certificate_message
      attr_reader :algorithm

      # @param certificate_message [TTTLS13::Message::Certificate]
      # @param algorithm [CertificateCompressionAlgorithm]
      def initialize(certificate_message:, algorithm:)
        @msg_type = HandshakeType::COMPRESSED_CERTIFICATE
        @certificate_message = certificate_message
        @algorithm = algorithm
      end

      # @return [String]
      def serialize
        binary = ''
        binary += @algorithm
        ct_bin = @certificate_message.serialize[4..]
        binary += ct_bin.length.to_uint24
        case @algorithm
        when Extension::CertificateCompressionAlgorithm::ZLIB
          binary += Zlib::Deflate.deflate(ct_bin).prefix_uint24_length
        else # TODO: BROTLI, ZSTD
          raise Error::ErrorAlerts, :internal_error
        end

        @msg_type + binary.prefix_uint24_length
      end

      alias fragment serialize

      # @param binary [String]
      #
      # @raise [TTTLS13::Error::ErrorAlerts]
      #
      # @return [TTTLS13::Message::CompressedCertificate]
      # rubocop: disable Metrics/AbcSize
      # rubocop: disable Metrics/CyclomaticComplexity
      # rubocop: disable Metrics/PerceivedComplexity
      def self.deserialize(binary)
        raise Error::ErrorAlerts, :internal_error if binary.nil?
        raise Error::ErrorAlerts, :decode_error if binary.length < 5
        raise Error::ErrorAlerts, :internal_error \
          unless binary[0] == HandshakeType::COMPRESSED_CERTIFICATE

        msg_len = Convert.bin2i(binary.slice(1, 3))
        algorithm = binary.slice(4, 2)
        uncompressed_length = Convert.bin2i(binary.slice(6, 3))
        ccm_len = Convert.bin2i(binary.slice(9, 3))
        ct_bin = ''
        case algorithm
        when Extension::CertificateCompressionAlgorithm::ZLIB
          ct_bin = Zlib::Inflate.inflate(binary.slice(12, ccm_len))
        else # TODO: BROTLI, ZSTD
          raise Error::ErrorAlerts, :bad_certificate
        end

        raise Error::ErrorAlerts, :bad_certificate \
          unless ct_bin.length == uncompressed_length
        raise Error::ErrorAlerts, :decode_error \
          unless ccm_len + 12 == binary.length && msg_len + 4 == binary.length

        certificate_message = Certificate.deserialize(
          HandshakeType::CERTIFICATE + ct_bin.prefix_uint24_length
        )
        CompressedCertificate.new(
          certificate_message: certificate_message,
          algorithm: algorithm
        )
      end
      # rubocop: enable Metrics/AbcSize
      # rubocop: enable Metrics/CyclomaticComplexity
      # rubocop: enable Metrics/PerceivedComplexity
    end
  end
end
