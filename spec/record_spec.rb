require 'spec_helper'

RSpec.describe Record do
  context 'valid record header' do
    let(:record) do
      Record.new(
        type: ContentType::HANDSHAKE,
        legacy_record_version: ProtocolVersion::TLS_1_2
      )
    end

    it 'should generate valid record' do
      expect(record.type).to eq ContentType::HANDSHAKE
      expect(record.legacy_record_version).to eq ProtocolVersion::TLS_1_2
      expect(record.length).to eq 0
    end

    it 'should serialize' do
      expect(record.serialize).to eq [0x16, 0x03, 0x03, 0x00, 0x00]
    end
  end

  context 'valid record header binary' do
    let(:record) do
      Record.deserialize(TESTBINARY_RECORD_HEADER, Passer.new)
    end

    it 'should generate valid record' do
      expect(record.type).to eq ContentType::HANDSHAKE
      expect(record.legacy_record_version).to eq ProtocolVersion::TLS_1_2
      expect(record.length).to eq 0
    end
  end

  context 'invalid record header binary, too short' do
    let(:record) do
      Record.deserialize(TESTBINARY_RECORD_HEADER[0...-1],
                         Passer.new)
    end

    it 'should not generate record' do
      expect { record }.to raise_error(RuntimeError)
    end
  end

  context 'invalid record header binary, binary is nil' do
    let(:record) do
      Record.deserialize(nil, Passer.new)
    end

    it 'should not generate record' do
      expect { record }.to raise_error(RuntimeError)
    end
  end
end
