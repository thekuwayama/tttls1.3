# encoding: ascii-8bit
# frozen_string_literal: true

require 'openssl'

module TLS13
  module Message
    class Certificate
      attr_reader :msg_type
      attr_reader :certificate_request_context
      attr_reader :certificate_list

      # @param certificate_request_context [String]
      # @param certificate_list [Array of CertificateEntry]
      def initialize(certificate_request_context: '',
                     certificate_list: [])
        @msg_type = HandshakeType::CERTIFICATE
        @certificate_request_context = certificate_request_context || ''
        @certificate_list = certificate_list || []
      end

      # @return [Integer]
      def length
        4 + @certificate_request_context.length \
        + @certificate_list.map(&:length).sum
      end

      # @return [String]
      def serialize
        binary = ''
        binary += @msg_type
        binary += i2uint24(length)
        binary += i2uint8(@certificate_request_context.length)
        binary += @certificate_request_context
        binary += i2uint24(@certificate_list.map(&:length).sum)
        binary += @certificate_list.map(&:serialize).join
        binary
      end

      alias fragment serialize

      # @param binary [String]
      #
      # @raise [RuntimeError]
      #
      # @return [TLS13::Message::Certificate]
      def self.deserialize(binary)
        raise 'invalid HandshakeType' \
          unless binary[0] == HandshakeType::CERTIFICATE

        msg_len = bin2i(binary.slice(1, 3))
        crc_len = bin2i(binary.slice(4, 1))
        certificate_request_context = binary.slice(5, crc_len)
        itr = 5 + crc_len
        cl_tail = itr + bin2i(binary.slice(itr, 3)) + 3
        itr += 3
        certificate_list \
        = deserialize_certificate_list(binary.slice(itr, cl_tail))
        raise 'malformed binary' unless msg_len + 4 == binary.length

        Certificate.new(
          certificate_request_context: certificate_request_context,
          certificate_list: certificate_list
        )
      end

      # @param binary [String]
      #
      # @return [Array of CertificateEntry]
      def self.deserialize_certificate_list(binary)
        itr = 0
        certificate_list = []
        while itr < binary.length
          cd_len = bin2i(binary.slice(itr, 3))
          itr += 3
          serialized_cert_data = binary.slice(itr, cd_len)
          cert_data = OpenSSL::X509::Certificate.new(serialized_cert_data)
          itr += cd_len
          exs_len = bin2i(binary.slice(itr, 2))
          itr += 2
          serialized_extension = binary.slice(itr, exs_len)
          extensions = Extensions.deserialize(serialized_extension,
                                              HandshakeType::CERTIFICATE)
          itr += exs_len
          certificate_list \
          << CertificateEntry.new(cert_data, extensions)
        end
        certificate_list
      end
    end

    class CertificateEntry
      attr_reader :cert_data
      attr_reader :extensions

      # @param cert_data [OpenSSL::X509::Certificate]
      # @param extensions [TLS13::Message::Extensions]
      #
      # @return [CertificateEntry]
      def initialize(cert_data, extensions = Extensions.new)
        @cert_data = cert_data
        @extensions = extensions || Extensions.new
      end

      # @return [Integer]
      def length
        5 + @cert_data.to_der.length + @extensions.length
      end

      # @return [String]
      def serialize
        binary = ''
        binary += i2uint24(@cert_data.to_der.length)
        binary += @cert_data.to_der
        binary += @extensions.serialize
        binary
      end
    end
  end
end
