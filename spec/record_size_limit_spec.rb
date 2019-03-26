# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe RecordSizeLimit do
  context 'vailid record_size_limit' do
    let(:extension) do
      RecordSizeLimit.new(2**14)
    end

    it 'should be generated' do
      expect(extension.extension_type).to eq ExtensionType::RECORD_SIZE_LIMIT
      expect(extension.record_size_limit).to eq 2**14
    end

    it 'should be serialized' do
      expect(extension.serialize).to eq ExtensionType::RECORD_SIZE_LIMIT \
                                        + i2uint16(2) \
                                        + i2uint16(2**14)
    end
  end

  context 'invalid record_size_limit' do
    let(:extension) do
      RecordSizeLimit.new(64)
    end

    it 'should not generated' do
      expect { extension }.to raise_error(RuntimeError)
    end
  end

  context 'valid record_size_limit binary' do
    let(:extension) do
      RecordSizeLimit.deserialize(TESTBINARY_RECORD_SIZE_LIMIT)
    end

    it 'should generate valid object' do
      expect(extension.extension_type).to eq ExtensionType::RECORD_SIZE_LIMIT
      expect(extension.record_size_limit).to eq 2**14
    end

    it 'should generate serializable object' do
      expect(extension.serialize).to eq ExtensionType::RECORD_SIZE_LIMIT \
                                        + uint16_length_prefix(
                                          TESTBINARY_RECORD_SIZE_LIMIT
                                        )
    end
  end
end
