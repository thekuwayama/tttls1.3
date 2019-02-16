module TLS13
  module Message
    module Extension
      module CertificateStatusType
        OCSP = 1
      end

      CERTIFICATE_STATUS_TYPE_ALLVALUE =
        CertificateStatusType.constants
                             .map(&CertificateStatusType.method(:const_get))
                             .to_set

      class StatusRequest
        attr_accessor :extension_type
        attr_accessor :length
        attr_accessor :request

        # @param request [Hash]
        #
        # @raise [RuntimeError]
        #
        # @return [TLS13::Message::Extension::StatusRequest]
        #
        # @example
        #   StatusRequest.new(
        #     request: { CertificateStatusType::OCSP => [
        #       [], # Array of Array of Integer,
        #       [], # Array of Integer
        #     ]}
        #   )
        def initialize(request: { CertificateStatusType::OCSP => [[], []] })
          @extension_type = ExtensionType::STATUS_REQUEST
          @request = request || {}
          @length = 0
          return if @request.empty?

          raise 'unknown status_type' unless
            request.keys.to_set.subset?(CERTIFICATE_STATUS_TYPE_ALLVALUE)

          @request.each do |status_type, value|
            if status_type == CertificateStatusType::OCSP # rubocop:disable all
              @length += 1
              @length += 2 + value[0].length * 2 + value[0].map(&:length).sum
              @length += 2 + value[1].length
            end
          end
        end

        # @return [Array of Integer]
        def serialize
          binary = []
          binary += @extension_type
          binary += i2uint16(@length)
          return binary if @request.nil?

          @request.each do |name_type, value|
            binary << name_type
            if name_type == CertificateStatusType::OCSP # rubocop:disable all
              binary += i2uint16(value[0].length)
              binary += value[0].map do |id|
                i2uint16(id.length) + id
              end
              binary += i2uint16(value[1].length)
              binary += value[1]
            end
          end
          binary
        end

        # @param binary [Array of Integer]
        #
        # @return [TLS13::Message::StatusRequest]
        def self.deserialize(binary)
          return StatusRequest.new(request: nil) if binary.nil? || binary.empty?

          status_type = binary[0]
          itr = 1
          request = {}
          while itr < binary.length
            if status_type == CertificateStatusType::OCSP
              l = arr2i([binary[itr], binary[itr + 1]])
              request_id = deserialize_request_id(binary.slice(itr + 2, l))
              itr += 2 + l
              l = arr2i([binary[itr], binary[itr + 1]])
              extensions = deserialize_extensions(binary.slice(itr + 2, l))
              itr += 2 + l
              request[status_type] = [request_id, extensions]
            else
              request[status_type] = binary[itr..-1]
            end
          end
          StatusRequest.new(request: request)
        end

        # @param binary [Array of Integer]
        #
        # @return [Array of Array of Integer]
        def self.deserialize_request_id(binary)
          itr = 0
          request_id = []
          while itr < binary.length
            l = arr2i([binary[itr], binary[itr + 1]])
            itr += 2
            request_id << binary.slice(itr, l) unless l.zero?
            itr += l
          end
          request_id
        end

        # @param binary [Array of Integer]
        #
        # @return [Array of Integer]
        def self.deserialize_extensions(binary)
          return [] if binary.nil? || binary.empty?

          binary
        end
      end
    end
  end
end
