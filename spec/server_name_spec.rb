# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

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
                                        + i2uint16(16) \
                                        + i2uint16(14) \
                                        + NameType::HOST_NAME \
                                        + i2uint16(11) \
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
                                        + i2uint16(0)
    end
  end

  context 'invalid server_name, too long HostName,' do
    let(:extension) do
      ServerName.new('a' * (2**16 - 4))
    end

    it 'should not be generated' do
      expect { extension }.to raise_error(RuntimeError)
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
      expect(extension.serialize).to eq ExtensionType::SERVER_NAME \
                                        + uint16_length_prefix(
                                          TESTBINARY_SERVER_NAME
                                        )
    end
  end

  context 'invalid server_name binary, malformed binary,' do
    let(:extension) do
      ServerName.deserialize(TESTBINARY_SERVER_NAME[0...-1])
    end

    it 'should not generate object' do
      expect { extension }.to raise_error(RuntimeError)
    end
  end

  context 'invalid server_name binary, unknown NameType,' do
    let(:extension) do
      host_name = i2uint16(16) + i2uint16(14) + "\xff" \
                  + i2uint16(11) + 'example.com'
      ServerName.deserialize(host_name)
    end

    it 'should not generate object' do
      expect { extension }.to raise_error(RuntimeError)
    end
  end

  context 'invalid server_name binary, empty HostName,' do
    let(:extension) do
      host_name = i2uint16(5) + i2uint16(3) + NameType::HOST_NAME \
                  + i2uint16(0) + ''
      ServerName.deserialize(host_name)
    end

    it 'should not generate object' do
      expect { extension }.to raise_error(RuntimeError)
    end
  end

  context 'invalid server_name binary, too long HostName,' do
    let(:extension) do
      host_name = i2uint16(5) + i2uint16(3) + NameType::HOST_NAME \
                  + i2uint16(2**16 - 4) + 'a' * (2**16 - 4)
      ServerName.deserialize(host_name)
    end

    it 'should not generate object' do
      expect { extension }.to raise_error(RuntimeError)
    end
  end
end
