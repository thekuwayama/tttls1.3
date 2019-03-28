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

      # @return [String]
      def serialize
        binary = ''
        binary += uint8_length_prefix(@certificate_request_context)
        binary += uint24_length_prefix(@certificate_list.map(&:serialize).join)

        @msg_type + uint24_length_prefix(binary)
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
        cl_len = bin2i(binary.slice(itr, 3))
        itr += 3
        cl_bin = binary.slice(itr, cl_len)
        itr += cl_len
        certificate_list = deserialize_certificate_list(cl_bin)
        raise 'malformed binary' unless msg_len + 4 == binary.length &&
                                        itr == binary.length

        Certificate.new(
          certificate_request_context: certificate_request_context,
          certificate_list: certificate_list
        )
      end

      class << self
        # @param binary [String]
        #
        # @return [Array of CertificateEntry]
        def deserialize_certificate_list(binary)
          itr = 0
          certificate_list = []
          while itr < binary.length
            cd_len = bin2i(binary.slice(itr, 3))
            itr += 3
            cd_bin = binary.slice(itr, cd_len)
            cert_data = OpenSSL::X509::Certificate.new(cd_bin)
            itr += cd_len
            exs_len = bin2i(binary.slice(itr, 2))
            itr += 2
            exs_bin = binary.slice(itr, exs_len)
            extensions = Extensions.deserialize(exs_bin,
                                                HandshakeType::CERTIFICATE)
            itr += exs_len
            certificate_list \
            << CertificateEntry.new(cert_data, extensions)
          end
          certificate_list
        end
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

      # @return [String]
      def serialize
        binary = ''
        binary += uint24_length_prefix(@cert_data.to_der)
        binary += @extensions.serialize
        binary
      end
    end
  end
end
