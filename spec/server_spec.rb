# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'spec_helper'
using Refinements

RSpec.describe Server do
  context 'server' do
    let(:message) do
      msg_len = TESTBINARY_CLIENT_HELLO.length
      mock_socket = SimpleStream.new
      mock_socket.write(ContentType::HANDSHAKE \
                        + ProtocolVersion::TLS_1_2 \
                        + msg_len.to_uint16 \
                        + TESTBINARY_CLIENT_HELLO)
      server = Server.new(mock_socket)
      server.send(:recv_client_hello)
    end

    it 'should receive ClientHello' do
      expect(message.msg_type).to eq HandshakeType::CLIENT_HELLO
      expect(message.legacy_version).to eq ProtocolVersion::TLS_1_2
      expect(message.legacy_compression_methods).to eq ["\x00"]
    end
  end
end
