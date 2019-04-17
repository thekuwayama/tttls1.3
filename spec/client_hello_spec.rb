# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'
using Refinements

RSpec.describe ClientHello do
  context 'default client_hello' do
    let(:random) do
      OpenSSL::Random.random_bytes(32)
    end

    let(:legacy_session_id) do
      Array.new(32, 0).map(&:chr).join
    end

    let(:cipher_suites) do
      CipherSuites.new([TLS_AES_256_GCM_SHA384,
                        TLS_CHACHA20_POLY1305_SHA256,
                        TLS_AES_128_GCM_SHA256])
    end

    let(:message) do
      ClientHello.new(random: random,
                      legacy_session_id: legacy_session_id,
                      cipher_suites: cipher_suites)
    end

    it 'should be generated' do
      expect(message.msg_type).to eq HandshakeType::CLIENT_HELLO
      expect(message.legacy_version).to eq ProtocolVersion::TLS_1_2
      expect(message.random).to eq random
      expect(message.legacy_session_id).to eq legacy_session_id
      expect(message.cipher_suites).to eq [TLS_AES_256_GCM_SHA384,
                                           TLS_CHACHA20_POLY1305_SHA256,
                                           TLS_AES_128_GCM_SHA256]
      expect(message.legacy_compression_methods).to eq ["\x00"]
      expect(message.extensions).to be_empty
    end

    it 'should be serialized' do
      expect(message.serialize).to eq HandshakeType::CLIENT_HELLO \
                                      + 79.to_uint24 \
                                      + ProtocolVersion::TLS_1_2 \
                                      + random \
                                      + legacy_session_id.length.to_uint8 \
                                      + legacy_session_id \
                                      + cipher_suites.serialize \
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
    end

    it 'should generate valid serializable object' do
      expect(message.serialize).to eq TESTBINARY_CLIENT_HELLO
    end
  end

  context 'valid client_hello binary, 0-RTT,' do
    let(:message) do
      ClientHello.deserialize(TESTBINARY_0_RTT_CLIENT_HELLO)
    end

    it 'should generate valid object' do
      expect(message.msg_type).to eq HandshakeType::CLIENT_HELLO
      expect(message.legacy_version).to eq ProtocolVersion::TLS_1_2
    end

    it 'should generate valid serializable object' do
      expect(message.serialize).to eq TESTBINARY_0_RTT_CLIENT_HELLO
    end
  end
end
