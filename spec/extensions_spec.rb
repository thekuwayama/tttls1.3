# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Extensions do
  context 'empty extensions' do
    let(:extensions) do
      Extensions.new
    end

    it 'should be generated' do
      expect(extensions).to be_empty
    end

    it 'should be serialized' do
      expect(extensions.serialize).to eq "\x00\x00"
    end
  end

  let(:base_exs) do
    exs = []
    # supported_versions: TLS_1_3
    exs << SupportedVersions.new(
      msg_type: HandshakeType::CLIENT_HELLO,
      versions: [ProtocolVersion::TLS_1_3]
    )
    # signature_algorithms
    exs << SignatureAlgorithms.new(
      [SignatureScheme::RSA_PSS_RSAE_SHA256]
    )
    # supported_groups: only P-256
    exs << SupportedGroups.new(
      [NamedGroup::SECP256R1]
    )
    # key_share: only P-256
    ec = OpenSSL::PKey::EC.new('prime256v1')
    ec.generate_key!
    exs << KeyShare.new(
      msg_type: HandshakeType::CLIENT_HELLO,
      key_share_entry: [
        KeyShareEntry.new(
          group: NamedGroup::SECP256R1,
          key_exchange: ec.public_key.to_octet_string(:uncompressed)
        )
      ]
    )
    # server_name
    exs << ServerName.new('example.com')
  end

  context 'client_hello base extensions' do
    let(:extensions) do
      Extensions.new(base_exs)
    end

    it 'should be generated' do
      expect(extensions).to include ExtensionType::SUPPORTED_VERSIONS
      expect(extensions).to include ExtensionType::SIGNATURE_ALGORITHMS
      expect(extensions).to include ExtensionType::SUPPORTED_GROUPS
      expect(extensions).to include ExtensionType::KEY_SHARE
      expect(extensions).to include ExtensionType::SERVER_NAME
    end
  end

  context 'extensions that include pre_shared_key' do
    let(:extensions) do
      pre_shared_key = PreSharedKey.deserialize(TESTBINARY_PRE_SHARED_KEY,
                                                HandshakeType::CLIENT_HELLO)
      Extensions.new(base_exs.unshift(pre_shared_key))
    end

    it 'should be generated' do
      expect(extensions).to include ExtensionType::SUPPORTED_VERSIONS
      expect(extensions).to include ExtensionType::SIGNATURE_ALGORITHMS
      expect(extensions).to include ExtensionType::SUPPORTED_GROUPS
      expect(extensions).to include ExtensionType::KEY_SHARE
      expect(extensions).to include ExtensionType::SERVER_NAME
      expect(extensions).to include ExtensionType::PRE_SHARED_KEY
    end

    it 'should be serialized end with pre_shared_key' do
      expect(extensions.serialize).to end_with TESTBINARY_PRE_SHARED_KEY
    end
  end
end
