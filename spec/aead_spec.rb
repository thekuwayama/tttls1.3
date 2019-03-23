# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Aead do
  context 'aead using CipherSuite::TLS_AES_128_GCM_SHA256' do
    let(:cipher) do
      Aead.new(cipher_suite: CipherSuite::TLS_AES_128_GCM_SHA256,
               write_key: TESTBINARY_SERVER_PARAMETERS_WRITE_KEY,
               write_iv: TESTBINARY_SERVER_PARAMETERS_WRITE_IV,
               sequence_number: SequenceNumber.new,
               inner_type: ContentType::HANDSHAKE)
    end

    let(:content) do
      TESTBINARY_SERVER_PARAMETERS
    end

    let(:encrypted_record) do
      TESTBINARY_SERVER_PARAMETERS_RECORD[5..]
    end

    let(:record_header) do
      TESTBINARY_SERVER_PARAMETERS_RECORD[0...5]
    end

    it 'should encrypt content of server parameters' do
      expect(cipher.encrypt(content)).to eq encrypted_record
    end

    it 'should decrypt encrypted_record server parameters' do
      expect(cipher.decrypt(encrypted_record, record_header)).to eq content
    end
  end

  context 'aead using CipherSuite::TLS_AES_128_GCM_SHA256' do
    let(:cipher) do
      Aead.new(cipher_suite: CipherSuite::TLS_AES_128_GCM_SHA256,
               write_key: TESTBINARY_CLIENT_FINISHED_WRITE_KEY,
               write_iv: TESTBINARY_CLIENT_FINISHED_WRITE_IV,
               sequence_number: SequenceNumber.new,
               inner_type: ContentType::HANDSHAKE)
    end

    let(:content) do
      TESTBINARY_CLIENT_FINISHED
    end

    let(:encrypted_record) do
      TESTBINARY_CLIENT_FINISHED_RECORD[5..]
    end

    let(:record_header) do
      TESTBINARY_CLIENT_FINISHED_RECORD[0...5]
    end

    it 'should encrypt content of client finished' do
      expect(cipher.encrypt(content)).to eq encrypted_record
    end

    it 'should decrypt encrypted_record client finished' do
      expect(cipher.decrypt(encrypted_record, record_header)).to eq content
    end
  end
end
