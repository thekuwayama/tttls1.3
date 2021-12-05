# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'spec_helper'
using Refinements

RSpec.describe Record do
  context 'valid record' do
    let(:record) do
      Record.new(
        type: ContentType::CCS,
        legacy_record_version: ProtocolVersion::TLS_1_2,
        messages: [ChangeCipherSpec.new],
        cipher: Passer.new
      )
    end

    it 'should be generated' do
      expect(record.type).to eq ContentType::CCS
      expect(record.legacy_record_version).to eq ProtocolVersion::TLS_1_2
    end

    it 'should be serialized' do
      expect(record.serialize).to eq ContentType::CCS \
                                     + ProtocolVersion::TLS_1_2 \
                                     + 1.to_uint16 \
                                     + ChangeCipherSpec.new.serialize
    end
  end

  context 'valid record binary' do
    let(:record) do
      Record.deserialize(TESTBINARY_RECORD_CCS, Passer.new).first
    end

    it 'should generate valid record header and ChangeCipherSpec' do
      expect(record.type).to eq ContentType::CCS
      expect(record.legacy_record_version).to eq ProtocolVersion::TLS_1_2
    end

    it 'should generate valid serializable object' do
      expect(record.serialize).to eq  ContentType::CCS \
                                     + ProtocolVersion::TLS_1_2 \
                                     + 1.to_uint16 \
                                     + ChangeCipherSpec.new.serialize
    end
  end

  context 'invalid record binary, too short,' do
    let(:record) do
      Record.deserialize(TESTBINARY_RECORD_CCS[0...-1],
                         Passer.new)
    end

    it 'should not generate object' do
      expect { record }.to raise_error(ErrorAlerts)
    end
  end

  context 'invalid record binary, nil,' do
    let(:record) do
      Record.deserialize(nil, Passer.new)
    end

    it 'should not generate object' do
      expect { record }.to raise_error(ErrorAlerts)
    end
  end

  context 'server parameters record binary' do
    let(:record) do
      cipher = Cryptograph::Aead.new(
        cipher_suite: CipherSuite::TLS_AES_128_GCM_SHA256,
        write_key: TESTBINARY_SERVER_PARAMETERS_WRITE_KEY,
        write_iv: TESTBINARY_SERVER_PARAMETERS_WRITE_IV,
        sequence_number: SequenceNumber.new
      )
      Record.deserialize(TESTBINARY_SERVER_PARAMETERS_RECORD, cipher).first
    end

    it 'should generate valid record header' do
      expect(record.type).to eq ContentType::APPLICATION_DATA
      expect(record.legacy_record_version).to eq ProtocolVersion::TLS_1_2
    end

    it 'should generate valid server parameters' do
      expect(record.messages[0].msg_type)
        .to eq HandshakeType::ENCRYPTED_EXTENSIONS
      expect(record.messages[0].serialize)
        .to eq TESTBINARY_ENCRYPTED_EXTENSIONS
      expect(record.messages[1].msg_type)
        .to eq HandshakeType::CERTIFICATE
      expect(record.messages[1].serialize)
        .to eq TESTBINARY_CERTIFICATE
      expect(record.messages[2].msg_type)
        .to eq HandshakeType::CERTIFICATE_VERIFY
      expect(record.messages[2].serialize)
        .to eq TESTBINARY_CERTIFICATE_VERIFY
      expect(record.messages[3].msg_type)
        .to eq HandshakeType::FINISHED
      expect(record.messages[3].serialize)
        .to eq TESTBINARY_SERVER_FINISHED
    end
  end
end
