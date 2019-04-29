# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'spec_helper'
using Refinements

RSpec.describe KeyShare do
  context 'valid key_share, KeyShareClientHello,' do
    let(:public_key_secp384r1) do
      "\x04" + OpenSSL::Random.random_bytes(96)
    end

    let(:public_key_secp256r1) do
      "\x04" + OpenSSL::Random.random_bytes(64)
    end

    let(:extension) do
      KeyShare.new(
        msg_type: HandshakeType::CLIENT_HELLO,
        key_share_entry: [
          KeyShareEntry.new(
            group: NamedGroup::SECP384R1,
            key_exchange: public_key_secp384r1
          ),
          KeyShareEntry.new(
            group: NamedGroup::SECP256R1,
            key_exchange: public_key_secp256r1
          )
        ]
      )
    end

    it 'should be generated' do
      expect(extension.msg_type).to eq HandshakeType::CLIENT_HELLO
      expect(extension.extension_type).to eq ExtensionType::KEY_SHARE
      expect(extension.key_share_entry[0].group).to eq NamedGroup::SECP384R1
      expect(extension.key_share_entry[0].key_exchange)
        .to eq public_key_secp384r1
      expect(extension.key_share_entry[1].group).to eq NamedGroup::SECP256R1
      expect(extension.key_share_entry[1].key_exchange)
        .to eq public_key_secp256r1
    end

    it 'should be serialized' do
      expect(extension.serialize)
        .to eq ExtensionType::KEY_SHARE \
               + 172.to_uint16 \
               + 170.to_uint16 \
               + NamedGroup::SECP384R1 \
               + NamedGroup.key_exchange_len(NamedGroup::SECP384R1).to_uint16 \
               + public_key_secp384r1 \
               + NamedGroup::SECP256R1 \
               + NamedGroup.key_exchange_len(NamedGroup::SECP256R1).to_uint16 \
               + public_key_secp256r1
    end
  end

  context 'valid key_share, empty KeyShare.client_shares vector' do
    let(:extension) do
      KeyShare.new(
        msg_type: HandshakeType::CLIENT_HELLO,
        key_share_entry: []
      )
    end

    it 'should be generated' do
      expect(extension.msg_type).to eq HandshakeType::CLIENT_HELLO
      expect(extension.extension_type).to eq ExtensionType::KEY_SHARE
      expect(extension.key_share_entry).to be_empty
    end

    it 'should be serialized' do
      expect(extension.serialize).to eq ExtensionType::KEY_SHARE \
                                        + 2.to_uint16 \
                                        + 0.to_uint16
    end
  end

  context 'valid key_share, KeyShareServerHello,' do
    let(:public_key_secp256r1) do
      "\x04" + OpenSSL::Random.random_bytes(64)
    end

    let(:extension) do
      KeyShare.new(
        msg_type: HandshakeType::SERVER_HELLO,
        key_share_entry: [
          KeyShareEntry.new(
            group: NamedGroup::SECP256R1,
            key_exchange: public_key_secp256r1
          )
        ]
      )
    end

    it 'should be generated' do
      expect(extension.msg_type).to eq HandshakeType::SERVER_HELLO
      expect(extension.extension_type).to eq ExtensionType::KEY_SHARE
      expect(extension.key_share_entry[0].group).to eq NamedGroup::SECP256R1
      expect(extension.key_share_entry[0].key_exchange)
        .to eq public_key_secp256r1
    end

    it 'should be serialized' do
      expect(extension.serialize)
        .to eq ExtensionType::KEY_SHARE \
               + 69.to_uint16 \
               + NamedGroup::SECP256R1 \
               + public_key_secp256r1.prefix_uint16_length
    end
  end

  context 'valid key_share, KeyShareHelloRetryRequest,' do
    let(:extension) do
      KeyShare.new(
        msg_type: HandshakeType::HELLO_RETRY_REQUEST,
        key_share_entry: [
          KeyShareEntry.new(
            group: NamedGroup::SECP256R1,
            key_exchange: nil
          )
        ]
      )
    end

    it 'should be generated' do
      expect(extension.msg_type).to eq HandshakeType::HELLO_RETRY_REQUEST
      expect(extension.extension_type).to eq ExtensionType::KEY_SHARE
      expect(extension.key_share_entry[0].group).to eq NamedGroup::SECP256R1
      expect(extension.key_share_entry[0].key_exchange).to be_empty
    end

    it 'should be serialized' do
      expect(extension.serialize)
        .to eq ExtensionType::KEY_SHARE \
               + NamedGroup::SECP256R1.prefix_uint16_length
    end
  end

  context 'valid key_share binary, KeyShareClientHello,' do
    let(:extension) do
      KeyShare.deserialize(TESTBINARY_KEY_SHARE_CH, HandshakeType::CLIENT_HELLO)
    end

    it 'should generate valid object' do
      expect(extension.msg_type).to eq HandshakeType::CLIENT_HELLO
      expect(extension.extension_type).to eq ExtensionType::KEY_SHARE
      expect(extension.key_share_entry[0].group).to eq NamedGroup::SECP256R1
      expect(extension.key_share_entry[0].key_exchange.length)
        .to eq NamedGroup.key_exchange_len(NamedGroup::SECP256R1)
    end

    it 'should generate serializable object' do
      expect(extension.serialize)
        .to eq ExtensionType::KEY_SHARE \
               + TESTBINARY_KEY_SHARE_CH.prefix_uint16_length
    end
  end

  context 'valid key_share binary, KeyShareServerHello,' do
    let(:extension) do
      KeyShare.deserialize(TESTBINARY_KEY_SHARE_SH, HandshakeType::SERVER_HELLO)
    end

    it 'should generate valid object' do
      expect(extension.msg_type).to eq HandshakeType::SERVER_HELLO
      expect(extension.extension_type).to eq ExtensionType::KEY_SHARE
      expect(extension.key_share_entry[0].group).to eq NamedGroup::SECP256R1
      expect(extension.key_share_entry[0].key_exchange.length)
        .to eq NamedGroup.key_exchange_len(NamedGroup::SECP256R1)
    end

    it 'should generate serializable object' do
      expect(extension.serialize)
        .to eq ExtensionType::KEY_SHARE \
               + TESTBINARY_KEY_SHARE_SH.prefix_uint16_length
    end
  end

  context 'valid key_share binary, KeyShareHelloRetryRequest,' do
    let(:extension) do
      KeyShare.deserialize(TESTBINARY_KEY_SHARE_HRR,
                           HandshakeType::HELLO_RETRY_REQUEST)
    end

    it 'should generate valid object' do
      expect(extension.msg_type).to eq HandshakeType::HELLO_RETRY_REQUEST
      expect(extension.extension_type).to eq ExtensionType::KEY_SHARE
      expect(extension.key_share_entry[0].group).to eq NamedGroup::SECP256R1
      expect(extension.key_share_entry[0].key_exchange).to be_empty
    end

    it 'should generate serializable object' do
      expect(extension.serialize)
        .to eq ExtensionType::KEY_SHARE \
               + TESTBINARY_KEY_SHARE_HRR.prefix_uint16_length
    end
  end
end
