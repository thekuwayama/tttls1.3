# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  using Refinements
  module Message
    # https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-1
    APPEARABLE_NST_EXTENSIONS = [
      ExtensionType::EARLY_DATA
    ].freeze
    private_constant :APPEARABLE_NST_EXTENSIONS

    class NewSessionTicket
      attr_reader :msg_type, :ticket_lifetime, :ticket_age_add, :ticket_nonce, :ticket, :extensions, :timestamp

      # @param ticket_lifetime [Integer]
      # @param ticket_age_add [String]
      # @param ticket_nonce [String]
      # @param ticket [String]
      # @param extensions [TTTLS13::Message::Extensions]
      #
      # @raise [TTTLS13::Error::ErrorAlerts]
      def initialize(ticket_lifetime:, ticket_age_add:,
                     ticket_nonce:, ticket:, extensions: Extensions.new)
        @msg_type = HandshakeType::NEW_SESSION_TICKET
        @ticket_lifetime = ticket_lifetime
        @ticket_age_add = ticket_age_add
        raise Error::ErrorAlerts, :internal_error \
          unless ticket_age_add.length == 4

        @ticket_nonce = ticket_nonce
        @ticket = ticket
        @extensions = extensions || Extensions.new
        @timestamp = Time.now.to_i
      end

      # @return [String]
      def serialize
        binary = ''
        binary += @ticket_lifetime.to_uint32
        binary += @ticket_age_add
        binary += @ticket_nonce.prefix_uint8_length
        binary += @ticket.prefix_uint16_length
        binary += @extensions.serialize

        @msg_type + binary.prefix_uint24_length
      end

      # @param binary [String]
      #
      # @raise [TTTLS13::Error::ErrorAlerts]
      #
      # @return [TTTLS13::Message::NewSessionTicket]
      # rubocop: disable Metrics/AbcSize
      def self.deserialize(binary)
        raise Error::ErrorAlerts, :internal_error if binary.nil?
        raise Error::ErrorAlerts, :decode_error if binary.length < 13
        raise Error::ErrorAlerts, :internal_error \
          unless binary[0] == HandshakeType::NEW_SESSION_TICKET

        msg_len = Convert.bin2i(binary.slice(1, 3))
        ticket_lifetime = Convert.bin2i(binary.slice(4, 4))
        ticket_age_add = binary.slice(8, 4)
        tn_len = Convert.bin2i(binary[12])
        ticket_nonce = binary.slice(13, tn_len)
        i = 13 + tn_len
        ticket_len = Convert.bin2i(binary.slice(i, 2))
        i += 2
        ticket = binary.slice(i, ticket_len)
        i += ticket_len
        exs_len = Convert.bin2i(binary.slice(i, 2))
        i += 2
        exs_bin = binary.slice(i, exs_len)
        extensions = Extensions.deserialize(exs_bin,
                                            HandshakeType::NEW_SESSION_TICKET)
        i += exs_len
        raise Error::ErrorAlerts, :decode_error unless i == msg_len + 4 &&
                                                       i == binary.length

        NewSessionTicket.new(ticket_lifetime:,
                             ticket_age_add:,
                             ticket_nonce:,
                             ticket:,
                             extensions:)
      end
      # rubocop: enable Metrics/AbcSize

      # @return [Boolean]
      def appearable_extensions?
        exs = @extensions.keys - APPEARABLE_NST_EXTENSIONS
        return true if exs.empty?

        !(exs - DEFINED_EXTENSIONS).empty?
      end
    end
  end
end
