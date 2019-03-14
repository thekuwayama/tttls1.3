# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
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

        # @return [Integer]
        def length
          3 + @responder_id_list.length * 2 \
          + @responder_id_list.map(&:length).sum \
          + 2 + @request_extensions.length
        end

        # @return [String]
        def serialize
          binary = ''
          binary += @extension_type
          binary += i2uint16(length)
          binary += CertificateStatusType::OCSP
          binary += i2uint16(@responder_id_list.length)
          binary += @responder_id_list.map do |id|
            i2uint16(id.length) + id
          end.join
          binary += uint16_length_prefix(@request_extensions)
          binary
        end

        # @param binary [String]
        #
        # @raise [RuntimeError]
        #
        # @return [TLS13::Message::Extension::StatusRequest]
        def self.deserialize(binary)
          raise 'too short binary' if binary.nil? || binary.length < 5

          raise 'unknown status_type' \
            unless binary[0] == CertificateStatusType::OCSP

          ril_len = bin2i(binary.slice(1, 2))
          itr = 3
          responder_id_list =
            deserialize_request_ids(binary.slice(itr, ril_len))
          itr += ril_len
          re_len = bin2i(binary.slice(itr, 2))
          itr += 2
          request_extensions = deserialize_extensions(binary.slice(itr, re_len))
          itr += re_len
          raise 'malformed binary' unless itr == binary.length

          StatusRequest.new(responder_id_list: responder_id_list,
                            request_extensions: request_extensions)
        end

        # @param binary [String]
        #
        # @raise [RuntimeError]
        #
        # @return [Array of String]
        def self.deserialize_request_ids(binary)
          return [] if binary.nil? || binary.empty?

          itr = 0
          request_ids = []
          while itr < binary.length
            id_len = bin2i(binary.slice(itr, 2))
            itr += 2
            id = binary.slice(itr, id_len) || ''
            request_ids += id
            itr += id_len
          end
          raise 'malformed binary' unless itr == binary.length

          request_ids
        end

        # @param binary [String]
        #
        # @return [String]
        def self.deserialize_extensions(binary)
          return '' if binary.nil? || binary.empty?

          binary
        end
      end
    end
  end
end
