# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'spec_helper'
using Refinements

RSpec.describe NewSessionTicket do
  context 'new_session_ticket' do
    let(:ticket_lifetime) do
      7200 # two_hours
    end

    let(:ticket_age_add) do
      OpenSSL::Random.random_bytes(4)
    end

    let(:ticket_nonce) do
      "\x00" * 255
    end

    let(:ticket) do
      OpenSSL::Random.random_bytes(255)
    end

    let(:message) do
      NewSessionTicket.new(ticket_lifetime:,
                           ticket_age_add:,
                           ticket_nonce:,
                           ticket:)
    end

    it 'should be generated' do
      expect(message.msg_type).to eq HandshakeType::NEW_SESSION_TICKET
      expect(message.ticket_lifetime).to eq ticket_lifetime
      expect(message.ticket_age_add).to eq ticket_age_add
      expect(message.ticket_nonce).to eq ticket_nonce
      expect(message.ticket).to eq ticket
      expect(message.extensions).to be_empty
    end

    it 'should be serialized' do
      expect(message.serialize).to eq HandshakeType::NEW_SESSION_TICKET \
                                      + 523.to_uint24 \
                                      + ticket_lifetime.to_uint32 \
                                      + ticket_age_add \
                                      + ticket_nonce.prefix_uint8_length \
                                      + ticket.prefix_uint16_length \
                                      + Extensions.new.serialize
    end
  end

  context 'new_session_ticket, invalid ticket_age_add,' do
    let(:message) do
      NewSessionTicket.new(ticket_lifetime: 60 * 60 * 2, # 2 hours
                           ticket_age_add: OpenSSL::Random.random_bytes(32),
                           ticket_nonce: "\x00" * 255,
                           ticket: OpenSSL::Random.random_bytes(255))
    end

    it 'should not be generated' do
      expect { message }.to raise_error(ErrorAlerts)
    end
  end

  context 'valid new_session_ticket binary' do
    let(:message) do
      NewSessionTicket.deserialize(TESTBINARY_NEW_SESSION_TICKET)
    end

    it 'should generate object' do
      expect(message.msg_type).to eq HandshakeType::NEW_SESSION_TICKET
      expect(message.ticket_lifetime).to eq 30
      expect(message.ticket_nonce).to eq "\x00\x00"
    end

    it 'should generate serializable object' do
      expect(message.serialize).to eq TESTBINARY_NEW_SESSION_TICKET
    end
  end
end
