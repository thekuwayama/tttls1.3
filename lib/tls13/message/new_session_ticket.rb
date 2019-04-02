# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  using Refinements
  module Message
    class NewSessionTicket
      attr_reader :msg_type
      attr_reader :ticket_lifetime
      attr_reader :ticket_age_add
      attr_reader :ticket_nonce
      attr_reader :ticket
      attr_reader :extensions

      SEVEN_DAYS = 60 * 60 * 24 * 7

      # @param ticket_lifetime [Integer]
      # @param ticket_age_add [String]
      # @param ticket_nonce [String]
      # @param ticket [String]
      # @param extensions [TLS13::Message::Extensions]
      #
      # @raise [TLS13::Error::InternalError]
      def initialize(ticket_lifetime:, ticket_age_add:,
                     ticket_nonce:, ticket:, extensions: Extensions.new)
        @msg_type = HandshakeType::NEW_SESSION_TICKET
        @ticket_lifetime = ticket_lifetime
        @ticket_age_add = ticket_age_add
        raise Error::InternalError unless ticket_age_add.length == 4

        @ticket_nonce = ticket_nonce
        @ticket = ticket
        @extensions = extensions || Extensions.new
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
      # @raise [TLS13::Error::InternalError, TLSError]
      #
      # @return [TLS13::Message::NewSessionTicket]
      # rubocop: disable Metrics/AbcSize
      def self.deserialize(binary)
        raise Error::InternalError if binary.nil?
        raise Error::TLSError, :decode_error if binary.length < 13
        raise Error::InternalError \
          unless binary[0] == HandshakeType::NEW_SESSION_TICKET

        msg_len = Convert.bin2i(binary.slice(1, 3))
        ticket_lifetime = Convert.bin2i(binary.slice(4, 4))
        ticket_age_add = binary.slice(8, 4)
        tn_len = Convert.bin2i(binary[12])
        ticket_nonce = binary.slice(13, tn_len)
        itr = 13 + tn_len
        ticket_len = Convert.bin2i(binary.slice(itr, 2))
        itr += 2
        ticket = binary.slice(itr, ticket_len)
        itr += ticket_len
        exs_len = Convert.bin2i(binary.slice(itr, 2))
        itr += 2
        exs_bin = binary.slice(itr, exs_len)
        extensions = Extensions.deserialize(exs_bin,
                                            HandshakeType::NEW_SESSION_TICKET)
        itr += exs_len
        raise Error::TLSError, :decode_error unless itr == msg_len + 4 &&
                                                    itr == binary.length

        NewSessionTicket.new(ticket_lifetime: ticket_lifetime,
                             ticket_age_add: ticket_age_add,
                             ticket_nonce: ticket_nonce,
                             ticket: ticket,
                             extensions: extensions)
      end
      # rubocop: enable Metrics/AbcSize
    end
  end
end
