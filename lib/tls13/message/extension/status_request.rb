# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  using Refinements
  module Message
    module Extension
      module CertificateStatusType
        OCSP = "\x01"
      end

      class StatusRequest
        attr_reader :extension_type
        attr_reader :responder_id_list
        attr_reader :request_extensions

        # @param responder_id_list [Array of String]
        # @param request_extensions [String]
        #
        # @example
        #   StatusRequest.new(
        #       responder_id_list: [],
        #       request_extensions: []
        #   )
        def initialize(responder_id_list: [], request_extensions: '')
          @extension_type = ExtensionType::STATUS_REQUEST
          @responder_id_list = responder_id_list || []
          @request_extensions = request_extensions || ''
        end

        # @return [String]
        def serialize
          binary = ''
          binary += CertificateStatusType::OCSP
          binary += @responder_id_list.length.to_uint16
          binary += @responder_id_list.map do |id|
            id.length.to_uint16 + id
          end.join
          binary += @request_extensions.prefix_uint16_length

          @extension_type + binary.prefix_uint16_length
        end

        # @param binary [String]
        #
        # @raise [TLS13::Error::TLSError]
        #
        # @return [TLS13::Message::Extension::StatusRequest, nil]
        # rubocop: disable Metrics/CyclomaticComplexity
        def self.deserialize(binary)
          raise Error::TLSError, :internal_error if binary.nil?
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
          request_extensions = binary.slice(i, re_len)
          i += re_len
          return nil unless i == binary.length

          StatusRequest.new(responder_id_list: responder_id_list,
                            request_extensions: request_extensions)
        end
        # rubocop: enable Metrics/CyclomaticComplexity

        class << self
          private

          # @param binary [String]
          #
          # @raise [TLS13::Error::TLSError]
          #
          # @return [Array of String, nil] received unparsable binary, nil
          def deserialize_request_ids(binary)
            raise Error::TLSError, :internal_error if binary.nil?

            i = 0
            request_ids = []
            while i < binary.length
              return nil if i + 2 > binary.length

              id_len = Convert.bin2i(binary.slice(i, 2))
              i += 2
              id = binary.slice(i, id_len)
              request_ids += id
              i += id_len
            end
            return nil if i != binary.length

            request_ids
          end
        end
      end
    end
  end
end
