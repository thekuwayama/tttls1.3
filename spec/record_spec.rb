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

    it 'should serialize binary' do
      expect(record.serialize).to eq [0x16, 0x03, 0x03, 0x00, 0x00]
    end
  end
end
