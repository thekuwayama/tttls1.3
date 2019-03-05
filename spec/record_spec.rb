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
end
