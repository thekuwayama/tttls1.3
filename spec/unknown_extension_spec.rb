# encoding: ascii-8bit

require 'spec_helper'

RSpec.describe UknownExtension do
  context 'valid uknown extension, no extension_data' do
    let(:extension) do
      UknownExtension.new(extension_type: "\x8a\x8a")
    end

    it 'should generate valid uknown extension' do
      expect(extension.extension_type).to eq "\x8a\x8a"
      expect(extension.length).to eq 0
      expect(extension.extension_data).to be_empty
    end

    it 'should serialize' do
      expect(extension.serialize).to eq "\x8a\x8a\x00\x00"
    end
  end

  context 'valid uknown extension' do
    let(:random_bytes) do
      OpenSSL::Random.random_bytes(20)
    end

    let(:extension) do
      UknownExtension.new(extension_type: "\x8a\x8a",
                          extension_data: random_bytes)
    end

    it 'should generate valid uknown extension' do
      expect(extension.extension_type).to eq "\x8a\x8a"
      expect(extension.length).to eq random_bytes.length
      expect(extension.extension_data).to eq random_bytes
    end

    it 'should serialize' do
      expect(extension.serialize).to eq "\x8a\x8a" \
                                        + i2uint16(random_bytes.length) \
                                        + random_bytes
    end
  end

  context 'invalid uknown extension' do
    let(:extension) do
      UknownExtension.new
    end

    it 'should not generate uknown extension' do
      expect { extension }.to raise_error(RuntimeError)
    end
  end

  context 'valid uknown extension binary, binary is nil' do
    let(:extension) do
      UknownExtension.deserialize(nil, "\x8a\x8a")
    end

    it 'should generate valid uknown extension' do
      expect(extension.extension_type).to eq "\x8a\x8a"
      expect(extension.length).to eq 0
      expect(extension.extension_data).to be_empty
    end
  end

  context 'valid uknown extension binary, binary is empty' do
    let(:extension) do
      UknownExtension.deserialize([], "\x8a\x8a")
    end

    it 'should generate valid uknown extension' do
      expect(extension.extension_type).to eq "\x8a\x8a"
      expect(extension.length).to eq 0
      expect(extension.extension_data).to be_empty
    end
  end

  context 'valid uknown extension binary' do
    let(:random_bytes) do
      OpenSSL::Random.random_bytes(20)
    end

    let(:extension) do
      UknownExtension.deserialize(random_bytes, "\x8a\x8a")
    end

    it 'should generate valid uknown extension' do
      expect(extension.extension_type).to eq "\x8a\x8a"
      expect(extension.length).to eq random_bytes.length
      expect(extension.extension_data).to eq random_bytes
    end
  end
end
