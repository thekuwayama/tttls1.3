# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe SupportedVersions do
  context 'valid supported_versions' do
    let(:extension) do
      SupportedVersions.new(
        msg_type: HandshakeType::CLIENT_HELLO,
        versions: [ProtocolVersion::TLS_1_3]
      )
    end

    it 'should be generated' do
      expect(extension.extension_type).to eq ExtensionType::SUPPORTED_VERSIONS
      expect(extension.length).to eq 3
      expect(extension.versions).to eq [ProtocolVersion::TLS_1_3]
    end

    it 'should be serialized' do
      expect(extension.serialize).to eq "\x00\x2b\x00\x03\x02\x03\x04"
    end
  end

  context 'default supported_versions' do
    let(:extension) do
      SupportedVersions.new(msg_type: HandshakeType::CLIENT_HELLO)
    end

    it 'should be generated' do
      expect(extension.extension_type).to eq ExtensionType::SUPPORTED_VERSIONS
      expect(extension.length).to eq 3
      expect(extension.versions).to eq [ProtocolVersion::TLS_1_3]
    end

    it 'should be serialized' do
      expect(extension.serialize).to eq "\x00\x2b\x00\x03\x02\x03\x04"
    end
  end

  context 'valid supported_versions binary' do
    let(:extension) do
      SupportedVersions.deserialize(TESTBINARY_SUPPORTED_VERSIONS,
                                    HandshakeType::CLIENT_HELLO)
    end

    it 'should generate valid object' do
      expect(extension.extension_type).to eq ExtensionType::SUPPORTED_VERSIONS
      expect(extension.length).to eq 3
      expect(extension.versions).to eq [ProtocolVersion::TLS_1_3]
    end
  end
end
