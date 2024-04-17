# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'spec_helper'
using Refinements

RSpec.describe ECHClientHello do
  context 'valid ECHClientHello outer binary' do
    let(:extension) do
      ECHClientHello.deserialize(TESTBINARY_ECH_OUTER)
    end

    it 'should generate valid object' do
      expect(extension.extension_type)
        .to eq ExtensionType::ENCRYPTED_CLIENT_HELLO
      expect(extension.type).to eq ECHClientHelloType::OUTER
      expect(extension.cipher_suite.kdf_id.uint16).to eq 1
      expect(extension.cipher_suite.aead_id.uint16).to eq 1
      expect(extension.config_id).to eq 32
      expect(extension.enc.length).to eq 32
      expect(extension.payload.length).to eq 239
    end

    it 'should be serialized' do
      expect(extension.serialize)
        .to eq ExtensionType::ENCRYPTED_CLIENT_HELLO \
               + 281.to_uint16 \
               + ECHClientHelloType::OUTER \
               + 1.to_uint16 \
               + 1.to_uint16 \
               + 32.to_uint8 \
               + extension.enc.prefix_uint16_length \
               + extension.payload.prefix_uint16_length
    end
  end

  context 'valid ECHClientHello inner binary' do
    let(:extension) do
      ECHClientHello.deserialize(TESTBINARY_ECH_INNER)
    end

    it 'should generate valid object' do
      expect(extension.extension_type)
        .to eq ExtensionType::ENCRYPTED_CLIENT_HELLO
      expect(extension.type).to eq ECHClientHelloType::INNER
    end

    it 'should be serialized' do
      expect(extension.serialize)
        .to eq ExtensionType::ENCRYPTED_CLIENT_HELLO \
               + 1.to_uint16 \
               + ECHClientHelloType::INNER \
    end
  end

  context 'valid ECHEncryptedExtensions binary' do
    let(:extension) do
      ECHEncryptedExtensions.deserialize(TESTBINARY_ECH_EE)
    end

    it 'should generate valid object' do
      expect(extension.extension_type)
        .to eq ExtensionType::ENCRYPTED_CLIENT_HELLO
      expect(extension.retry_configs.is_a?(Array)).to be_truthy
      expect(extension.retry_configs.length).to eq 1
      expect(extension.retry_configs.first.is_a?(ECHConfig)).to be_truthy
    end
  end

  context 'valid ECHHelloRetryRequest binary' do
    let(:extension) do
      ECHHelloRetryRequest.deserialize(TESTBINARY_ECH_HRR)
    end

    it 'should generate valid object' do
      expect(extension.extension_type)
        .to eq ExtensionType::ENCRYPTED_CLIENT_HELLO
      expect(extension.confirmation).to eq "\x00" * 8
    end
  end
end

RSpec.describe Ech do
  context 'EncodedClientHelloInner length' do
    let(:server_name) do
      'localhost'
    end

    let(:client) do
      Client.new(nil, server_name)
    end

    let(:maximum_name_length) do
      0
    end

    let(:encoded) do
      extensions, = client.send(:gen_ch_extensions)
      inner_ech = Message::Extension::ECHClientHello.new_inner
      Message::ClientHello.new(
        legacy_session_id: '',
        cipher_suites: CipherSuites.new(DEFAULT_CH_CIPHER_SUITES),
        extensions: extensions.merge(
          Message::ExtensionType::ENCRYPTED_CLIENT_HELLO => inner_ech
        )
      )
    end

    let(:padding_encoded_ch_inner) do
      Ech.padding_encoded_ch_inner(
        encoded.serialize[4..],
        server_name.length,
        maximum_name_length
      )
    end

    it 'should be equal placeholder_encoded_ch_inner_len' do
      expect(Ech.placeholder_encoded_ch_inner_len)
        .to eq padding_encoded_ch_inner.length
    end
  end

  context 'removing and replacing extensions from EncodedClientHelloInner' do
    let(:extensions) do
      extensions, = Client.new(nil, 'localhost').send(:gen_ch_extensions)
      extensions
    end

    let(:no_key_share_exs) do
      Extensions.new(
        extensions.filter { |k, _| k != ExtensionType::KEY_SHARE }.values
      )
    end

    it 'should be equal remove_and_replace! with []' do
      cloned = extensions.clone
      expect(extensions.remove_and_replace!([]))
        .to eq cloned
    end

    it 'should be equal remove_and_replace! with [key_share]' do
      expected = extensions.filter { |k, _| k != ExtensionType::KEY_SHARE }
      expected[ExtensionType::ECH_OUTER_EXTENSIONS] = \
        Extension::ECHOuterExtensions.new([ExtensionType::KEY_SHARE])
      got = extensions.remove_and_replace!([ExtensionType::KEY_SHARE])
      expect(got.keys).to eq expected.keys
      expect(got[ExtensionType::ECH_OUTER_EXTENSIONS].outer_extensions)
        .to eq expected[ExtensionType::ECH_OUTER_EXTENSIONS].outer_extensions
    end

    it 'should be equal remove_and_replace! with no key_share extensions' \
       ' & [key_share]' do
      cloned = no_key_share_exs.clone
      expect(no_key_share_exs.remove_and_replace!([ExtensionType::KEY_SHARE]))
        .to eq cloned
    end
  end
end
