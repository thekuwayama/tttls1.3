# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  using Refinements
  module Message
    # https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-1
    APPEARABLE_CT_EXTENSIONS = [
      ExtensionType::STATUS_REQUEST,
      ExtensionType::SIGNED_CERTIFICATE_TIMESTAMP
    ].freeze
    private_constant :APPEARABLE_CT_EXTENSIONS

    class Certificate
      attr_reader :msg_type, :certificate_request_context, :certificate_list

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
        binary += @certificate_request_context.prefix_uint8_length
        binary += @certificate_list.map(&:serialize).join.prefix_uint24_length

        @msg_type + binary.prefix_uint24_length
      end

      alias fragment serialize

      # @param binary [String]
      #
      # @raise [TTTLS13::Error::ErrorAlerts]
      #
      # @return [TTTLS13::Message::Certificate]
      def self.deserialize(binary)
        raise Error::ErrorAlerts, :internal_error if binary.nil?
        raise Error::ErrorAlerts, :decode_error if binary.length < 5
        raise Error::ErrorAlerts, :internal_error \
          unless binary[0] == HandshakeType::CERTIFICATE

        msg_len = Convert.bin2i(binary.slice(1, 3))
        crc_len = Convert.bin2i(binary.slice(4, 1))
        certificate_request_context = binary.slice(5, crc_len)
        i = 5 + crc_len
        cl_len = Convert.bin2i(binary.slice(i, 3))
        i += 3
        cl_bin = binary.slice(i, cl_len)
        i += cl_len
        certificate_list = deserialize_certificate_list(cl_bin)
        raise Error::ErrorAlerts, :decode_error unless i == msg_len + 4 &&
                                                       i == binary.length

        Certificate.new(
          certificate_request_context:,
          certificate_list:
        )
      end

      # @return [Boolean]
      def appearable_extensions?
        cl_exs = @certificate_list.map do |e|
          e.instance_variable_get(:@extensions).keys
        end
        exs = cl_exs.uniq.flatten - APPEARABLE_CT_EXTENSIONS
        return true if exs.empty?

        !(exs - DEFINED_EXTENSIONS).empty?
      end

      class << self
        private

        # @param binary [String]
        #
        # @raise [TTTLS13::Error::ErrorAlerts]
        #
        # @return [Array of CertificateEntry]
        def deserialize_certificate_list(binary)
          raise Error::ErrorAlerts, :internal_error if binary.nil?

          i = 0
          certificate_list = []
          while i < binary.length
            raise Error::ErrorAlerts, :decode_error if i + 3 > binary.length

            cd_len = Convert.bin2i(binary.slice(i, 3))
            i += 3
            cd_bin = binary.slice(i, cd_len)
            cert_data = OpenSSL::X509::Certificate.new(cd_bin)
            i += cd_len
            raise Error::ErrorAlerts, :decode_error if i + 2 > binary.length

            exs_len = Convert.bin2i(binary.slice(i, 2))
            i += 2
            exs_bin = binary.slice(i, exs_len)
            extensions = Extensions.deserialize(exs_bin,
                                                HandshakeType::CERTIFICATE)
            i += exs_len
            certificate_list << CertificateEntry.new(cert_data, extensions)
          end
          raise Error::ErrorAlerts, :decode_error unless i == binary.length

          certificate_list
        end
      end
    end

    class CertificateEntry
      attr_reader :cert_data, :extensions

      # @param cert_data [OpenSSL::X509::Certificate]
      # @param extensions [TTTLS13::Message::Extensions]
      #
      # @return [CertificateEntry]
      def initialize(cert_data, extensions = Extensions.new)
        @cert_data = cert_data
        @extensions = extensions || Extensions.new
      end

      # @return [String]
      def serialize
        binary = ''
        binary += @cert_data.to_der.prefix_uint24_length
        binary += @extensions.serialize
        binary
      end
    end
  end
end
