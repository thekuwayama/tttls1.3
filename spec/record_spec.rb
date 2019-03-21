# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Record do
  context 'valid record' do
    let(:record) do
      Record.new(
        type: ContentType::CCS,
        legacy_record_version: ProtocolVersion::TLS_1_2,
        messages: [ChangeCipherSpec.new],
        cryptographer: Passer.new
      )
    end

    it 'should be generated' do
      expect(record.type).to eq ContentType::CCS
      expect(record.legacy_record_version).to eq ProtocolVersion::TLS_1_2
      expect(record.length).to eq 1
    end

    it 'should be serialized' do
      expect(record.serialize).to eq ContentType::CCS \
                                     + ProtocolVersion::TLS_1_2 \
                                     + i2uint16(1) \
                                     + ChangeCipherSpec.new.serialize
    end
  end

  context 'valid record binary' do
    let(:record) do
      Record.deserialize(TESTBINARY_RECORD_CCS, Passer.new)
    end

    it 'should generate valid record header and ChangeCipherSpec' do
      expect(record.type).to eq ContentType::CCS
      expect(record.legacy_record_version).to eq ProtocolVersion::TLS_1_2
      expect(record.length).to eq 1
    end

    it 'should generate valid serializable object' do
      expect(record.serialize).to eq  ContentType::CCS \
                                     + ProtocolVersion::TLS_1_2 \
                                     + i2uint16(1) \
                                     + ChangeCipherSpec.new.serialize
    end
  end

  context 'invalid record binary, too short,' do
    let(:record) do
      Record.deserialize(TESTBINARY_RECORD_CCS[0...-1],
                         Passer.new)
    end

    it 'should not generate object' do
      expect { record }.to raise_error(RuntimeError)
    end
  end

  context 'invalid record binary, nil,' do
    let(:record) do
      Record.deserialize(nil, Passer.new)
    end

    it 'should not generate object' do
      expect { record }.to raise_error(RuntimeError)
    end
  end

  context 'server parameters record binary' do
    let(:hash_len) do
      CipherSuite.hash_len(CipherSuite::TLS_AES_128_GCM_SHA256)
    end

    let(:record) do
      cipher = Cryptograph::Aead.new(
        cipher_suite: CipherSuite::TLS_AES_128_GCM_SHA256,
        key: TESTBINARY_SERVER_PARAMETERS_WRITE_KEY,
        nonce: TESTBINARY_SERVER_PARAMETERS_WRITE_IV,
        type: ContentType::HANDSHAKE
      )
      Record.deserialize(TESTBINARY_SERVER_PARAMETERS_RECORD, cipher)
    end

    it 'should generate valid record header' do
      expect(record.type).to eq ContentType::APPLICATION_DATA
      expect(record.legacy_record_version).to eq ProtocolVersion::TLS_1_2
    end

    it 'should generate valid server parameters' do
      server_parameters = Message.deserialize_server_parameters(
        record.messages.first.fragment,
        hash_len
      )

      expect(server_parameters[0].msg_type)
        .to eq HandshakeType::ENCRYPTED_EXTENSIONS
      expect(server_parameters[0].serialize)
        .to eq TESTBINARY_ENCRYPTED_EXTENSIONS
      expect(server_parameters[1].msg_type)
        .to eq HandshakeType::CERTIFICATE
      expect(server_parameters[1].serialize)
        .to eq TESTBINARY_CERTIFICATE
      expect(server_parameters[2].msg_type)
        .to eq HandshakeType::CERTIFICATE_VERIFY
      expect(server_parameters[2].serialize)
        .to eq TESTBINARY_CERTIFICATE_VERIFY
      expect(server_parameters[3].msg_type)
        .to eq HandshakeType::FINISHED
      expect(server_parameters[3].serialize)
        .to eq TESTBINARY_SERVER_FINISHED
    end
  end
end
