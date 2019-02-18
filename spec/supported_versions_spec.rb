require 'spec_helper'

RSpec.describe SupportedVersions do
  context 'valid supported_versions' do
    let(:extension) do
      SupportedVersions.new(versions: [ProtocolVersion::TLS_1_3])
    end

    it 'should generate valid supported_versions' do
      expect(extension.extension_type).to eq ExtensionType::SUPPORTED_VERSIONS
      expect(extension.length).to eq 3
      expect(extension.versions).to eq [ProtocolVersion::TLS_1_3]
    end
  end

  context 'default supported_versions' do
    let(:extension) do
      SupportedVersions.new
    end

    it 'should generate valid supported_versions' do
      expect(extension.extension_type).to eq ExtensionType::SUPPORTED_VERSIONS
      expect(extension.length).to eq 3
      expect(extension.versions).to eq [ProtocolVersion::TLS_1_3]
    end
  end

  context 'valid supported_versions binary' do
    let(:extension) do
      SupportedVersions.deserialize(TESTBINARY_SUPPORTED_VERSIONS)
    end

    it 'should generate valid supported_versions' do
      expect(extension.extension_type).to eq ExtensionType::SUPPORTED_VERSIONS
      expect(extension.length).to eq 3
      expect(extension.versions).to eq [ProtocolVersion::TLS_1_3]
    end
  end
end
