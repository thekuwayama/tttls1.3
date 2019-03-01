# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe ClientHello do
  context 'default client_hello' do
    let(:random) do
      OpenSSL::Random.random_bytes(32)
    end

    let(:legacy_session_id) do
      Array.new(32, 0).map(&:chr).join
    end

    let(:message) do
      ClientHello.new(random: random,
                      legacy_session_id: legacy_session_id)
    end

    it 'should be generate' do
      expect(message.msg_type).to eq HandshakeType::CLIENT_HELLO
      expect(message.length).to eq 79
      expect(message.legacy_version).to eq ProtocolVersion::TLS_1_2
      expect(message.random).to eq random
      expect(message.legacy_session_id).to eq legacy_session_id
      expect(message.cipher_suites).to eq DEFALT_CIPHER_SUITES
      expect(message.legacy_compression_methods).to eq 0
      expect(message.extensions).to be_empty
    end

    it 'should be serialize' do
      expect(message.serialize).to eq HandshakeType::CLIENT_HELLO \
                                      + i2uint24(message.length) \
                                      + ProtocolVersion::TLS_1_2 \
                                      + random \
                                      + i2uint8(legacy_session_id.length) \
                                      + legacy_session_id \
                                      + CipherSuites.new.serialize \
                                      + "\x01\x00" \
                                      + Extensions.new.serialize
    end
  end

  context 'valid client_hello binary' do
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
