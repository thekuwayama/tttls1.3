# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'spec_helper'
using Refinements

RSpec.describe ServerName do
  context 'valid server_name, example.com,' do
    let(:extension) do
      ServerName.new('example.com')
    end

    it 'should be generated' do
      expect(extension.extension_type).to eq ExtensionType::SERVER_NAME
      expect(extension.server_name).to eq 'example.com'
    end

    it 'should be serialized' do
      expect(extension.serialize).to eq ExtensionType::SERVER_NAME \
                                        + 16.to_uint16 \
                                        + 14.to_uint16 \
                                        + NameType::HOST_NAME \
                                        + 11.to_uint16 \
                                        + 'example.com'
    end
  end

  context 'valid server_name, empty HostName,' do
    let(:extension) do
      ServerName.new('')
    end

    it 'should be generated' do
      expect(extension.extension_type).to eq ExtensionType::SERVER_NAME
    end

    it 'should be serialized' do
      expect(extension.serialize).to eq ExtensionType::SERVER_NAME \
                                        + 0.to_uint16
    end
  end

  context 'invalid server_name, too long HostName,' do
    let(:extension) do
      ServerName.new('a' * (2**16 - 4))
    end

    it 'should not be generated' do
      expect { extension }.to raise_error(ErrorAlerts)
    end
  end

  context 'valid server_name binary' do
    let(:extension) do
      ServerName.deserialize(TESTBINARY_SERVER_NAME)
    end

    it 'should generate valid object' do
      expect(extension.extension_type).to eq ExtensionType::SERVER_NAME
      expect(extension.server_name).to eq 'github.com'
    end

    it 'should generate serializable object' do
      expect(extension.serialize)
        .to eq ExtensionType::SERVER_NAME \
               + TESTBINARY_SERVER_NAME.prefix_uint16_length
    end
  end

  context 'invalid server_name binary, malformed binary,' do
    let(:extension) do
      ServerName.deserialize(TESTBINARY_SERVER_NAME[0...-1])
    end

    it 'should return nil' do
      expect(extension).to be nil
    end
  end

  context 'invalid server_name binary, unknown NameType,' do
    let(:testbinary) do
      name_type = "\xff"
      binary = name_type + 'example.com'.prefix_uint16_length
      binary.prefix_uint16_length.prefix_uint16_length
    end

    let(:extension) do
      ServerName.deserialize(testbinary)
    end

    it 'should return nil' do
      expect(extension).to be nil
    end
  end

  context 'invalid server_name binary, empty HostName,' do
    let(:testbinary) do
      binary = NameType::HOST_NAME + ''.prefix_uint16_length
      binary.prefix_uint16_length.prefix_uint16_length
    end

    let(:extension) do
      ServerName.deserialize(testbinary)
    end

    it 'should return nil' do
      expect(extension).to be nil
    end
  end
end
