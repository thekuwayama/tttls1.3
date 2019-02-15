require 'spec_helper'

RSpec.describe ServerName do
  context 'valid server_name' do
    let(:extension) do
      ServerName.new(
        server_name: { NameType::HOST_NAME => 'example.com' }
      )
    end

    it 'should generate valid server_name' do
      expect(extension.extension_type).to eq ExtensionType::SERVER_NAME
      expect(extension.length).to eq 16
      expect(extension.server_name.keys).to include NameType::HOST_NAME
      expect(extension.server_name[NameType::HOST_NAME]).to eq 'example.com'
    end
  end

  context 'invalid server_name, undefined name_type' do
    let(:extension) do
      ServerName.new(
        server_name: { 1 => 'example.com' }
      )
    end

    it 'should not generate server_name' do
      expect { extension }.to raise_error(RuntimeError)
    end
  end

  context 'valid server_name binary' do
    let(:extension) do
      ServerName.deserialize(TESTBINARY_SERVER_NAME)
    end

    it 'should generate valid server_name' do
      expect(extension.extension_type).to eq ExtensionType::SERVER_NAME
      expect(extension.length).to eq 15
      expect(extension.server_name.keys).to include NameType::HOST_NAME
      expect(extension.server_name[NameType::HOST_NAME]).to eq 'github.com'
    end
  end
end
