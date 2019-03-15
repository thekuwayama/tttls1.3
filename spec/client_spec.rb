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

    let(:record_ch) do
      connection.send_client_hello
      Record.deserialize(mock_socket.read, Cryptograph::Passer.new)
    end

    it 'should send default ClientHello' do
      expect(record_ch.type).to eq ContentType::HANDSHAKE

      message = record_ch.messages.first
      expect(message.msg_type).to eq HandshakeType::CLIENT_HELLO
      expect(message.legacy_version).to eq ProtocolVersion::TLS_1_2
      expect(message.cipher_suites).to eq DEFALT_CIPHER_SUITES
      expect(message.legacy_compression_methods).to eq "\x00"
      expect(message.extensions).to be_empty
    end
  end

  context 'client' do
    let(:mock_socket) do
      SimpleStream.new
    end

    let(:connection) do
      Client.new(mock_socket)
    end

    let(:record_sh) do
      sh = ServerHello.deserialize(TESTBINARY_SERVER_HELLO)
      Record.new(type: ContentType::HANDSHAKE,
                 messages: [sh],
                 cryptographer: Cryptograph::Passer.new)
    end

    it 'should receive ServerHello' do
      mock_socket.write(record_sh.serialize)
      message = connection.recv_server_hello
      expect(message.msg_type).to eq HandshakeType::SERVER_HELLO
      expect(message.legacy_version).to eq ProtocolVersion::TLS_1_2
      expect(message.legacy_compression_method).to eq "\x00"
    end
  end
end
