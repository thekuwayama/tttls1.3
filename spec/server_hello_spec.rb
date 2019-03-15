# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe ServerHello do
  context 'default server_hello' do
    let(:random) do
      OpenSSL::Random.random_bytes(32)
    end

    let(:legacy_session_id_echo) do
      Array.new(32, 0).map(&:chr).join
    end

    let(:cipher_suite) do
      CipherSuite::TLS_AES_256_GCM_SHA384
    end

    let(:message) do
      ServerHello.new(random: random,
                      legacy_session_id_echo: legacy_session_id_echo,
                      cipher_suite: cipher_suite)
    end

    it 'should be generate' do
      expect(message.msg_type).to eq HandshakeType::SERVER_HELLO
      expect(message.length).to eq 72
      expect(message.legacy_version).to eq ProtocolVersion::TLS_1_2
      expect(message.random).to eq random
      expect(message.legacy_session_id_echo).to eq legacy_session_id_echo
      expect(message.cipher_suite).to eq CipherSuite::TLS_AES_256_GCM_SHA384
      expect(message.legacy_compression_method).to eq "\x00"
      expect(message.extensions).to be_empty
    end

    it 'should be serialize' do
      expect(message.serialize).to eq HandshakeType::SERVER_HELLO \
                                      + i2uint24(message.length) \
                                      + ProtocolVersion::TLS_1_2 \
                                      + random \
                                      + i2uint8(legacy_session_id_echo.length) \
                                      + legacy_session_id_echo \
                                      + cipher_suite \
                                      + "\x00" \
                                      + Extensions.new.serialize
    end
  end

  context 'valid server_hello binary' do
    let(:message) do
      ServerHello.deserialize(TESTBINARY_SERVER_HELLO)
    end

    it 'should generate valid object' do
      expect(message.msg_type).to eq HandshakeType::SERVER_HELLO
      expect(message.legacy_version).to eq ProtocolVersion::TLS_1_2
      expect(message.legacy_compression_method).to eq "\x00"
    end

    it 'should generate valid serializable object' do
      expect(message.serialize).to eq TESTBINARY_SERVER_HELLO
    end
  end
end
