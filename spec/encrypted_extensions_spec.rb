# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'spec_helper'
using Refinements

RSpec.describe EncryptedExtensions do
  context 'valid encrypted_extensions' do
    let(:server_name) do
      ServerName.new('')
    end

    let(:supported_groups) do
      SupportedGroups.new(
        [
          NamedGroup::SECP256R1,
          NamedGroup::SECP384R1,
          NamedGroup::SECP521R1
        ]
      )
    end

    let(:extensions) do
      Extensions.new([server_name, supported_groups])
    end

    let(:message) do
      EncryptedExtensions.new(extensions)
    end

    it 'should be generated' do
      expect(message.msg_type).to eq HandshakeType::ENCRYPTED_EXTENSIONS
      expect(message.extensions).to eq extensions
      expect(message.only_appearable_extensions?).to be true
    end

    it 'should be serialized' do
      expect(message.serialize)
        .to eq HandshakeType::ENCRYPTED_EXTENSIONS \
               + extensions.serialize.prefix_uint24_length
    end
  end

  context 'invalid encrypted_extensions, including forbidden extension type,' do
    let(:extensions) do
      signature_algorithms \
      = SignatureAlgorithms.new([SignatureScheme::ECDSA_SECP256R1_SHA256])
      Extensions.new([signature_algorithms])
    end

    let(:message) do
      EncryptedExtensions.new(extensions)
    end

    it 'should be generated' do
      expect(message.msg_type).to eq HandshakeType::ENCRYPTED_EXTENSIONS
      expect(message.extensions).to eq extensions
      expect(message.only_appearable_extensions?).to be false
    end
  end

  context 'valid encrypted_extensions, nil argument,' do
    let(:message) do
      EncryptedExtensions.new(nil)
    end

    it 'should be generated' do
      expect(message.msg_type).to eq HandshakeType::ENCRYPTED_EXTENSIONS
      expect(message.extensions).to eq Extensions.new
      expect(message.only_appearable_extensions?).to be true
    end

    it 'should be serialized' do
      expect(message.serialize)
        .to eq HandshakeType::ENCRYPTED_EXTENSIONS \
               + Extensions.new.serialize.prefix_uint24_length
    end
  end

  context 'valid encrypted_extensions binary' do
    let(:message) do
      EncryptedExtensions.deserialize(TESTBINARY_ENCRYPTED_EXTENSIONS)
    end

    it 'should generate valid object' do
      expect(message.msg_type).to eq HandshakeType::ENCRYPTED_EXTENSIONS
      expect(message.only_appearable_extensions?).to be true
    end

    it 'should generate valid serializable object' do
      expect(message.serialize).to eq TESTBINARY_ENCRYPTED_EXTENSIONS
    end
  end
end
