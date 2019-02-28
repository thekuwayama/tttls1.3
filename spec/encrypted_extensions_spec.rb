# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe EncryptedExtensions do
  context 'valid encrypted_extensions' do
    let(:server_name) do
      ServerName.new('example.com')
    end

    let(:supported_groups) do
      SupportedGroups.new
    end

    let(:extensions) do
      Extensions.new(ExtensionType::SERVER_NAME => server_name,
                     ExtensionType::SUPPORTED_GROUPS => supported_groups)
    end

    let(:message) do
      EncryptedExtensions.new(extensions)
    end

    it 'should be generate' do
      expect(message.msg_type).to eq HandshakeType::ENCRYPTED_EXTENSIONS
      expect(message.length).to eq 10 + server_name.length \
                                   + supported_groups.length
      expect(message.extensions).to eq extensions
    end

    it 'should be serialize' do
      expect(message.serialize).to eq HandshakeType::ENCRYPTED_EXTENSIONS \
                                      + i2uint24(message.length) \
                                      + extensions.serialize
    end
  end

  context 'valid encrypted_extensions, nil argument,' do
    let(:message) do
      EncryptedExtensions.new(nil)
    end

    it 'should be generate' do
      expect(message.msg_type).to eq HandshakeType::ENCRYPTED_EXTENSIONS
      expect(message.length).to eq 2
      expect(message.extensions).to eq Extensions.new
    end

    it 'should be serialize' do
      expect(message.serialize).to eq HandshakeType::ENCRYPTED_EXTENSIONS \
                                      + i2uint24(message.length) \
                                      + Extensions.new.serialize
    end
  end

  context 'valid encrypted_extensions binary' do
    let(:message) do
      EncryptedExtensions.deserialize(TESTBINARY_ENCRYPTED_EXTENSIONS)
    end

    it 'should generate valid object' do
      expect(message.msg_type).to eq HandshakeType::ENCRYPTED_EXTENSIONS
      expect(message.length).to eq 36
    end

    it 'should generate valid serializable object' do
      expect(message.serialize).to eq TESTBINARY_ENCRYPTED_EXTENSIONS
    end
  end
end
