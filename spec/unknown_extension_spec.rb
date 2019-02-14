require 'spec_helper'

RSpec.describe UknownExtension do
  context 'valid uknown extension, no extension_data' do
    let(:extension) do
      UknownExtension.new(extension_type: [0x8a, 0x8a])
    end

    it 'should generate valid uknown extension' do
      expect(extension.extension_type).to eq [0x8a, 0x8a]
      expect(extension.length).to eq 0
      expect(extension.extension_data).to eq nil
    end

    it 'should serialize' do
      expect(extension.serialize).to eq [0x8a, 0x8a, 0x00, 0x00]
    end
  end

  context 'valid uknown extension' do
    let(:rand_binary) do
      Array.new(20).map { rand(255) }
    end

    let(:extension) do
      UknownExtension.new(
        extension_type: [0x8a, 0x8a],
        extension_data: rand_binary
      )
    end

    it 'should generate valid uknown extension' do
      expect(extension.extension_type).to eq [0x8a, 0x8a]
      expect(extension.length).to eq rand_binary.length
      expect(extension.extension_data).to eq rand_binary
    end

    it 'should serialize' do
      expect(extension.serialize).to eq [0x8a, 0x8a] \
                                        + [rand_binary.length / (1 << 8),
                                           rand_binary.length % (1 << 8)] \
                                        + rand_binary
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
      UknownExtension.deserialize(nil, [0x8a, 0x8a])
    end

    it 'should generate valid uknown extension' do
      expect(extension.extension_type).to eq [0x8a, 0x8a]
      expect(extension.length).to eq 0
      expect(extension.extension_data).to eq nil
    end
  end

  context 'valid uknown extension binary, binary is empty' do
    let(:extension) do
      UknownExtension.deserialize([], [0x8a, 0x8a])
    end

    it 'should generate valid uknown extension' do
      expect(extension.extension_type).to eq [0x8a, 0x8a]
      expect(extension.length).to eq 0
      expect(extension.extension_data).to eq []
    end
  end

  context 'valid uknown extension binary' do
    let(:rand_binary) do
      Array.new(20).map { rand(255) }
    end

    let(:extension) do
      UknownExtension.deserialize(rand_binary, [0x8a, 0x8a])
    end

    it 'should generate valid uknown extension' do
      expect(extension.extension_type).to eq [0x8a, 0x8a]
      expect(extension.length).to eq rand_binary.length
      expect(extension.extension_data).to eq rand_binary
    end
  end
end
