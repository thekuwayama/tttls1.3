# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'spec_helper'
using Refinements

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

    it 'should be generated' do
      expect(message.msg_type).to eq HandshakeType::SERVER_HELLO
      expect(message.legacy_version).to eq ProtocolVersion::TLS_1_2
      expect(message.random).to eq random
      expect(message.legacy_session_id_echo).to eq legacy_session_id_echo
      expect(message.cipher_suite).to eq CipherSuite::TLS_AES_256_GCM_SHA384
      expect(message.legacy_compression_method).to eq "\x00"
      expect(message.extensions).to be_empty
    end

    it 'should be serialized' do
      expect(message.serialize).to eq HandshakeType::SERVER_HELLO \
                                      + 72.to_uint24 \
                                      + ProtocolVersion::TLS_1_2 \
                                      + random \
                                      + legacy_session_id_echo.length.to_uint8 \
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
      expect(message.cipher_suite).to eq CipherSuite::TLS_AES_128_GCM_SHA256
      expect(message.legacy_compression_method).to eq "\x00"
    end

    it 'should generate valid serializable object' do
      expect(message.serialize).to eq TESTBINARY_SERVER_HELLO
    end
  end

  context 'hello_retry_request binary' do
    let(:message) do
      ServerHello.deserialize(TESTBINARY_HRR_HELLO_RETRY_REQUEST)
    end

    it 'should generate valid object' do
      expect(message.msg_type).to eq HandshakeType::SERVER_HELLO
      expect(message.legacy_version).to eq ProtocolVersion::TLS_1_2
      expect(message.cipher_suite).to eq CipherSuite::TLS_AES_128_GCM_SHA256
      expect(message.legacy_compression_method).to eq "\x00"
      expect(message.hrr?).to be true
    end

    it 'should generate valid serializable object' do
      expect(message.serialize).to eq TESTBINARY_HRR_HELLO_RETRY_REQUEST
    end
  end

  context 'valid server_hello binary, 0-RTT,' do
    let(:message) do
      ServerHello.deserialize(TESTBINARY_0_RTT_SERVER_HELLO)
    end

    it 'should generate valid object' do
      expect(message.msg_type).to eq HandshakeType::SERVER_HELLO
      expect(message.legacy_version).to eq ProtocolVersion::TLS_1_2
      expect(message.cipher_suite).to eq CipherSuite::TLS_AES_128_GCM_SHA256
      expect(message.legacy_compression_method).to eq "\x00"
    end

    it 'should generate valid serializable object' do
      expect(message.serialize).to eq TESTBINARY_0_RTT_SERVER_HELLO
    end
  end

  context 'default hello_retry_request' do
    let(:legacy_session_id_echo) do
      Array.new(32, 0).map(&:chr).join
    end

    let(:cipher_suite) do
      CipherSuite::TLS_AES_256_GCM_SHA384
    end

    let(:message) do
      ServerHello.new(random: Message::HRR_RANDOM,
                      legacy_session_id_echo: legacy_session_id_echo,
                      cipher_suite: cipher_suite)
    end

    it 'should be generated' do
      expect(message.msg_type).to eq HandshakeType::SERVER_HELLO
      expect(message.legacy_version).to eq ProtocolVersion::TLS_1_2
      expect(message.random).to eq Message::HRR_RANDOM
      expect(message.legacy_session_id_echo).to eq legacy_session_id_echo
      expect(message.cipher_suite).to eq CipherSuite::TLS_AES_256_GCM_SHA384
      expect(message.legacy_compression_method).to eq "\x00"
      expect(message.extensions).to be_empty
      expect(message.hrr?).to eq true
    end

    it 'should be serialized' do
      expect(message.serialize).to eq HandshakeType::SERVER_HELLO \
                                      + 72.to_uint24 \
                                      + ProtocolVersion::TLS_1_2 \
                                      + Message::HRR_RANDOM \
                                      + legacy_session_id_echo.length.to_uint8 \
                                      + legacy_session_id_echo \
                                      + cipher_suite \
                                      + "\x00" \
                                      + Extensions.new.serialize
    end
  end
end
