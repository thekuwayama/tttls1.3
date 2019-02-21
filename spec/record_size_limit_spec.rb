require 'spec_helper'

RSpec.describe RecordSizeLimit do
  context 'vailid record_size_limit' do
    let(:extension) do
      RecordSizeLimit.new(2**14)
    end

    it 'should generate valid record_size_limit' do
      expect(extension.extension_type).to eq ExtensionType::RECORD_SIZE_LIMIT
      expect(extension.length).to eq 2
      expect(extension.record_size_limit).to eq 2**14
      expect(extension.serialize).to eq [0x00, 0x1c, 0x00, 0x02, 0x40, 0x00]
    end
  end

  context 'invalid record_size_limit' do
    let(:extension) do
      RecordSizeLimit.new(64)
    end

    it 'should not generate record_size_limit' do
      expect { extension }.to raise_error(RuntimeError)
    end
  end

  context 'valid record_size_limit binary' do
    let(:extension) do
      RecordSizeLimit.deserialize(TESTBINARY_RECORD_SIZE_LIMIT)
    end

    it 'should generate valid record_size_limit' do
      expect(extension.extension_type).to eq ExtensionType::RECORD_SIZE_LIMIT
      expect(extension.length).to eq 2
      expect(extension.record_size_limit).to eq 2**14
    end
  end
end
