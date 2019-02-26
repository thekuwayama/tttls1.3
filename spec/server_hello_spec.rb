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

    let(:cipher_suites) do
      CipherSuites.new([CipherSuite::TLS_AES_256_GCM_SHA384])
    end

    let(:message) do
      ServerHello.new(random: random,
                      legacy_session_id_echo: legacy_session_id_echo,
                      cipher_suites: cipher_suites)
    end

    it 'should be generate' do
      expect(message.msg_type).to eq HandshakeType::SERVER_HELLO
      expect(message.length).to eq 75
      expect(message.legacy_version).to eq ProtocolVersion::TLS_1_2
      expect(message.random).to eq random
      expect(message.legacy_session_id_echo).to eq legacy_session_id_echo
      expect(message.cipher_suites).to eq [CipherSuite::TLS_AES_256_GCM_SHA384]
      expect(message.legacy_compression_methods).to eq 0
      expect(message.extensions).to be_empty
    end

    it 'should be serialize' do
      expect(message.serialize).to eq HandshakeType::SERVER_HELLO \
                                      + i2uint24(message.length) \
                                      + ProtocolVersion::TLS_1_2 \
                                      + random \
                                      + i2uint8(legacy_session_id_echo.length) \
                                      + legacy_session_id_echo \
                                      + cipher_suites.serialize \
                                      + "\x01\x00" \
                                      + Extensions.new.serialize
    end
  end
end