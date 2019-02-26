# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe ClientHello do
  context 'default client_hello' do
    let(:message) do
      ClientHello.new
    end

    it 'should be generate' do
      expect(message.msg_type).to eq HandshakeType::CLIENT_HELLO
      expect(message.legacy_version).to eq ProtocolVersion::TLS_1_2
      expect(message.cipher_suites).to eq DEFALT_CIPHER_SUITES
      expect(message.extensions).to be_empty
    end
  end

  context 'valid client_hello' do
    let(:message) do
      ClientHello.deserialize(TESTBINARY_CLIENT_HELLO)
    end

    it 'should generate valid object' do
      expect(message.msg_type).to eq HandshakeType::CLIENT_HELLO
      expect(message.legacy_version).to eq ProtocolVersion::TLS_1_2
      expect(message.length).to eq 192
    end

    it 'should generate valid serializable object' do
      expect(message.serialize).to eq TESTBINARY_CLIENT_HELLO
    end
  end
end
