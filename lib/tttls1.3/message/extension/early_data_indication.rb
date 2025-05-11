# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  using Refinements
  module Message
    module Extension
      class EarlyDataIndication
        attr_reader :extension_type, :max_early_data_size

        # @param max_early_data_size [Integer, nil]
        #
        # @raise [TTTLS13::Error::ErrorAlerts]
        def initialize(max_early_data_size = nil)
          @extension_type = ExtensionType::EARLY_DATA
          @max_early_data_size = max_early_data_size
          raise Error::ErrorAlerts, :internal_error \
            unless @max_early_data_size.nil? || @max_early_data_size < 2**32
        end

        # @return [String]
        def serialize
          binary = ''
          binary = @max_early_data_size.to_uint32 \
            unless @max_early_data_size.nil?

          @extension_type + binary.prefix_uint16_length
        end

        # @param binary [String]
        # @param msg_type [TTTLS13::Message::ContentType]
        #
        # @raise [TTTLS13::Error::ErrorAlerts]
        #
        # @return [TTTLS13::Message::Extensions::EarlyDataIndication, nil]
        def self.deserialize(binary, msg_type)
          raise Error::ErrorAlerts, :internal_error if binary.nil?

          case msg_type
          when HandshakeType::CLIENT_HELLO, HandshakeType::ENCRYPTED_EXTENSIONS
            return nil unless binary.empty?

            max_early_data_size = nil
          when HandshakeType::NEW_SESSION_TICKET
            return nil unless binary.length == 4

            max_early_data_size = Convert.bin2i(binary)
          else
            raise Error::ErrorAlerts, :internal_error
          end

          EarlyDataIndication.new(max_early_data_size)
        end
      end
    end
  end
end
