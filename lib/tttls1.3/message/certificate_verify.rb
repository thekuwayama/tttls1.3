# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  using Refinements
  module Message
    class CertificateVerify
      attr_reader :msg_type
      attr_reader :signature_scheme
      attr_reader :signature

      # @param signature_scheme [TTTLS13::SignatureScheme]
      # @param signature [String]
      #
      # @raise [TTTLS13::Error::ErrorAlerts]
      def initialize(signature_scheme:, signature:)
        @msg_type = HandshakeType::CERTIFICATE_VERIFY
        @signature_scheme = signature_scheme
        @signature = signature
        raise Error::ErrorAlerts, :internal_error \
          if @signature.length > 2**16 - 1
      end

      # @return [String]
      def serialize
        binary = ''
        binary += @signature_scheme
        binary += @signature.prefix_uint16_length

        @msg_type + binary.prefix_uint24_length
      end

      alias fragment serialize

      # @param binary [String]
      #
      # @raise [TTTLS13::Error::ErrorAlerts]
      #
      # @return [TTTLS13::Message::CertificateVerify]
      def self.deserialize(binary)
        raise Error::ErrorAlerts, :internal_error if binary.nil?
        raise Error::ErrorAlerts, :decode_error if binary.length < 8
        raise Error::ErrorAlerts, :internal_error \
          unless binary[0] == HandshakeType::CERTIFICATE_VERIFY

        msg_len = Convert.bin2i(binary.slice(1, 3))
        signature_scheme = binary.slice(4, 2)
        signature_len = Convert.bin2i(binary.slice(6, 2))
        signature = binary.slice(8, signature_len)
        raise Error::ErrorAlerts, :decode_error \
          unless signature_len + 4 == msg_len &&
                 signature_len + 8 == binary.length

        CertificateVerify.new(signature_scheme: signature_scheme,
                              signature: signature)
      end
    end
  end
end
