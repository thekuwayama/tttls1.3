# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'spec_helper'
using Refinements

RSpec.describe SupportedVersions do
  context 'valid supported_versions of ClientHello' do
    let(:extension) do
      SupportedVersions.new(
        msg_type: HandshakeType::CLIENT_HELLO,
        versions: [ProtocolVersion::TLS_1_3, ProtocolVersion::TLS_1_2]
      )
    end

    it 'should be generated' do
      expect(extension.extension_type).to eq ExtensionType::SUPPORTED_VERSIONS
      expect(extension.versions).to eq [ProtocolVersion::TLS_1_3,
                                        ProtocolVersion::TLS_1_2]
    end

    it 'should be serialized' do
      expect(extension.serialize).to eq ExtensionType::SUPPORTED_VERSIONS \
                                        + 5.to_uint16 \
                                        + 4.to_uint8 \
                                        + ProtocolVersion::TLS_1_3 \
                                        + ProtocolVersion::TLS_1_2
    end
  end

  context 'default supported_versions of ClientHello' do
    let(:extension) do
      SupportedVersions.new(msg_type: HandshakeType::CLIENT_HELLO)
    end

    it 'should be generated' do
      expect(extension.extension_type).to eq ExtensionType::SUPPORTED_VERSIONS
      expect(extension.versions).to eq [ProtocolVersion::TLS_1_3]
    end

    it 'should be serialized' do
      expect(extension.serialize).to eq ExtensionType::SUPPORTED_VERSIONS \
                                        + 3.to_uint16 \
                                        + 2.to_uint8 \
                                        + ProtocolVersion::TLS_1_3
    end
  end

  context 'invalid supported_versions of ClientHello, empty,' do
    let(:extension) do
      SupportedVersions.new(msg_type: HandshakeType::CLIENT_HELLO,
                            versions: [])
    end

    it 'should not be generated' do
      expect { extension }.to raise_error(ErrorAlerts)
    end
  end

  context 'invalid supported_versions of ClientHello, too large,' do
    let(:extension) do
      SupportedVersions.new(msg_type: HandshakeType::CLIENT_HELLO,
                            versions: (0..127).to_a.map(&:to_uint16))
    end

    it 'should not be generated' do
      expect { extension }.to raise_error(ErrorAlerts)
    end
  end

  context 'valid supported_versions of ServerHello' do
    let(:extension) do
      SupportedVersions.new(msg_type: HandshakeType::SERVER_HELLO,
                            versions: [ProtocolVersion::TLS_1_3])
    end

    it 'should be generated' do
      expect(extension.extension_type).to eq ExtensionType::SUPPORTED_VERSIONS
      expect(extension.versions).to eq [ProtocolVersion::TLS_1_3]
    end

    it 'should be serialized' do
      expect(extension.serialize).to eq ExtensionType::SUPPORTED_VERSIONS \
                                        + 2.to_uint16 \
                                        + ProtocolVersion::TLS_1_3
    end
  end

  context 'invalid supported_versions of ServerHello, empty,' do
    let(:extension) do
      SupportedVersions.new(msg_type: HandshakeType::SERVER_HELLO,
                            versions: [])
    end

    it 'should not be generated' do
      expect { extension }.to raise_error(ErrorAlerts)
    end
  end

  context 'valid supported_versions binary, ClientHello' do
    let(:extension) do
      SupportedVersions.deserialize(TESTBINARY_SUPPORTED_VERSIONS_CH,
                                    HandshakeType::CLIENT_HELLO)
    end

    it 'should generate valid object' do
      expect(extension.extension_type).to eq ExtensionType::SUPPORTED_VERSIONS
      expect(extension.versions).to eq [ProtocolVersion::TLS_1_3,
                                        ProtocolVersion::TLS_1_2]
    end

    it 'should generate serializable object' do
      expect(extension.serialize)
        .to eq ExtensionType::SUPPORTED_VERSIONS \
               + TESTBINARY_SUPPORTED_VERSIONS_CH.prefix_uint16_length
    end
  end

  context 'valid supported_versions binary, ServerHello' do
    let(:extension) do
      SupportedVersions.deserialize(TESTBINARY_SUPPORTED_VERSIONS_SH,
                                    HandshakeType::SERVER_HELLO)
    end

    it 'should generate valid object' do
      expect(extension.extension_type).to eq ExtensionType::SUPPORTED_VERSIONS
      expect(extension.versions).to eq [ProtocolVersion::TLS_1_3]
    end

    it 'should generate serializable object' do
      expect(extension.serialize)
        .to eq ExtensionType::SUPPORTED_VERSIONS \
               + TESTBINARY_SUPPORTED_VERSIONS_SH.prefix_uint16_length
    end
  end
end
