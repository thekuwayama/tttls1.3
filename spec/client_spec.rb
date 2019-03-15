# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Client do
  context 'client' do
    let(:mock_socket) do
      SimpleStream.new
    end

    let(:connection) do
      Client.new(mock_socket)
    end

    it 'should send default ClientHello' do
      connection.send_client_hello
      record = Record.deserialize(mock_socket.read, Cryptograph::Passer.new)
      expect(record.type).to eq ContentType::HANDSHAKE

      message = record.messages.first
      expect(message.msg_type).to eq HandshakeType::CLIENT_HELLO
      expect(message.legacy_version).to eq ProtocolVersion::TLS_1_2
      expect(message.cipher_suites).to eq DEFALT_CIPHER_SUITES
      expect(message.legacy_compression_methods).to eq "\x00"
      expect(message.extensions).to be_empty
    end
  end
end
