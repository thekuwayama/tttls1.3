# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  using Refinements
  module Message
    module Extension
      module CertificateStatusType
        OCSP = "\x01"
      end

      class OCSPStatusRequest
        attr_reader :extension_type
        attr_reader :responder_id_list
        attr_reader :request_extensions

        # @param responder_id_list [Array of OpenSSL::ASN1::ASN1Data]
        # @param request_extensions [Array of OpenSSL::ASN1::ASN1Data]
        #
        # @example
        #   OCSPStatusRequest.new
        def initialize(responder_id_list: [], request_extensions: [])
          @extension_type = ExtensionType::STATUS_REQUEST
          @responder_id_list = responder_id_list || []
          @request_extensions = request_extensions || []
        end

        # @return [String]
        def serialize
          binary = ''
          binary += CertificateStatusType::OCSP
          binary += @responder_id_list.length.to_uint16
          binary += @responder_id_list.map do |id|
            id.to_der.prefix_uint16_length
          end.join
          binary += @request_extensions.map(&:to_der).join.prefix_uint16_length

          @extension_type + binary.prefix_uint16_length
        end

        # @param binary [String]
        #
        # @raise [TTTLS13::Error::ErrorAlerts]
        #
        # @return [TTTLS13::Message::Extension::OCSPStatusRequest, nil]
        # rubocop: disable Metrics/CyclomaticComplexity
        # rubocop: disable Metrics/PerceivedComplexity
        def self.deserialize(binary)
          raise Error::ErrorAlerts, :internal_error if binary.nil?
          return nil if binary.length < 5 ||
                        binary[0] != CertificateStatusType::OCSP

          ril_len = Convert.bin2i(binary.slice(1, 2))
          i = 3
          responder_id_list =
            deserialize_request_ids(binary.slice(i, ril_len))
          # unparsable responder_id_list
          return nil if responder_id_list.nil?

          i += ril_len
          return nil if i + 2 > binary.length

          re_len = Convert.bin2i(binary.slice(i, 2))
          i += 2
          exs_bin = binary.slice(i, re_len)
          begin
            request_extensions = OpenSSL::ASN1.decode_all(exs_bin)
          rescue OpenSSL::ASN1::ASN1Error
            return nil
          end
          i += re_len
          return nil unless i == binary.length

          OCSPStatusRequest.new(responder_id_list: responder_id_list,
                                request_extensions: request_extensions)
        end
        # rubocop: enable Metrics/CyclomaticComplexity
        # rubocop: enable Metrics/PerceivedComplexity

        class << self
          private

          # @param binary [String]
          #
          # @raise [TTTLS13::Error::ErrorAlerts]
          #
          # @return [Array of ASN1Data, nil] received unparsable binary, nil
          def deserialize_request_ids(binary)
            raise Error::ErrorAlerts, :internal_error if binary.nil?

            i = 0
            request_ids = []
            while i < binary.length
              return nil if i + 2 > binary.length

              id_len = Convert.bin2i(binary.slice(i, 2))
              i += 2
              id = binary.slice(i, id_len)
              begin
                request_ids += OpenSSL::ASN1.decode(id)
              rescue OpenSSL::ASN1::ASN1Error
                return nil
              end
              i += id_len
            end
            return nil if i != binary.length

            request_ids
          end
        end
      end

      class OCSPResponse
        attr_reader :extension_type
        attr_reader :ocsp_response

        # @param ocsp_response [OpenSSL::OCSP::Response]
        #
        # @example
        #   OCSPResponse.new(
        #     OpenSSL::OCSP::Response.create(status, basic_resp)
        #   )
        def initialize(ocsp_response)
          @extension_type = ExtensionType::STATUS_REQUEST
          @ocsp_response = ocsp_response
        end

        # @return [String]
        def serialize
          binary = ''
          binary += CertificateStatusType::OCSP
          binary += @ocsp_response.to_der.prefix_uint24_length

          @extension_type + binary.prefix_uint16_length
        end

        # @param binary [String]
        #
        # @raise [TTTLS13::Error::ErrorAlerts]
        #
        # @return [TTTLS13::Message::Extension::OCSPResponse, nil]
        def self.deserialize(binary)
          raise Error::ErrorAlerts, :internal_error if binary.nil?
          return nil if binary.length < 4 ||
                        binary[0] != CertificateStatusType::OCSP

          res_len = Convert.bin2i(binary.slice(1, 3))
          res = binary.slice(4, res_len)
          ocsp_response = nil
          begin
            ocsp_response = OpenSSL::OCSP::Response.new(res)
          rescue OpenSSL::OCSP::OCSPError
            return nil
          end
          return nil if 4 + res_len != binary.length

          OCSPResponse.new(ocsp_response)
        end
      end
    end
  end
end
