# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
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
      def initialize(ticket_lifetime:, ticket_age_add:,
                     ticket_nonce:, ticket:, extensions: Extensions.new)
        @msg_type = HandshakeType::NEW_SESSION_TICKET
        @ticket_lifetime = ticket_lifetime
        raise 'too long ticket_lifetime' if ticket_lifetime >= SEVEN_DAYS

        @ticket_age_add = ticket_age_add
        raise 'invalid ticket_age_add' unless ticket_age_add.length == 4

        @ticket_nonce = ticket_nonce
        @ticket = ticket
        @extensions = extensions || Extensions.new
      end

      # @return [String]
      def serialize
        binary = ''
        binary += i2uint32(@ticket_lifetime)
        binary += @ticket_age_add
        binary += uint8_length_prefix(@ticket_nonce)
        binary += uint16_length_prefix(@ticket)
        binary += @extensions.serialize
        @msg_type + uint24_length_prefix(binary)
      end

      # @param binary [String]
      #
      # @raise [RuntimeError]
      #
      # @return [TLS13::Message::NewSessionTicket]
      # rubocop: disable Metrics/AbcSize
      def self.deserialize(binary)
        raise 'invalid HandshakeType' \
          unless binary[0] == HandshakeType::NEW_SESSION_TICKET

        msg_len = bin2i(binary.slice(1, 3))
        ticket_lifetime = bin2i(binary.slice(4, 4))
        ticket_age_add = binary.slice(8, 4)
        tn_len = bin2i(binary[12])
        ticket_nonce = binary.slice(13, tn_len)
        itr = 13 + tn_len
        ticket_len = bin2i(binary.slice(itr, 2))
        itr += 2
        ticket = binary.slice(itr, ticket_len)
        itr += ticket_len
        exs_len = bin2i(binary.slice(itr, 2))
        itr += 2
        exs_bin = binary.slice(itr, exs_len)
        extensions = Extensions.deserialize(exs_bin,
                                            HandshakeType::NEW_SESSION_TICKET)
        itr += exs_len
        raise 'malformed binary' unless itr == msg_len + 4 &&
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
