# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Aead do
  context 'aead using CipherSuite::TLS_AES_128_GCM_SHA256' do
    let(:cipher) do
      Aead.new(type: ContentType::HANDSHAKE,
               nonce: TESTBINARY_SERVER_PARAMETERS_IV,
               key: TESTBINARY_SERVER_PARAMETERS_WRITE_KEY,
               cipher_suite: CipherSuite::TLS_AES_128_GCM_SHA256)
    end

    let(:content) do
      TESTBINARY_SERVER_PARAMETERS
    end

    let(:encrypted_record) do
      TESTBINARY_ENCRYPTED_SERVER_PARAMETERS
    end

    it 'should encrypt content' do
      expect(cipher.encrypt(content)).to eq encrypted_record
    end

    it 'should decrypt encrypted_record' do
      # expect(cipher.dencrypt(encrypted_record)).to eq content
    end
  end
end
