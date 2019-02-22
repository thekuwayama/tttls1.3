require 'spec_helper'

RSpec.describe KeyShare do
  context 'valid key_share (KeyShareClientHello)' do
    let(:public_key_x25519) do
      OpenSSL::Random.random_bytes(32).unpack('C*')
    end

    let(:public_key_secp256r1) do
      [0x04] + OpenSSL::Random.random_bytes(64).unpack('C*')
    end

    let(:extension) do
      KeyShare.new(
        msg_type: HandshakeType::CLIENT_HELLO,
        key_share_entry: [
          KeyShareEntry.new(
            group: NamedGroup::X25519,
            key_exchange: public_key_x25519
          ),
          KeyShareEntry.new(
            group: NamedGroup::SECP256R1,
            key_exchange: public_key_secp256r1
          )
        ]
      )
    end

    it 'should generate valid key_share' do
      expect(extension.msg_type).to eq HandshakeType::CLIENT_HELLO
      expect(extension.extension_type).to eq ExtensionType::KEY_SHARE
      expect(extension.length).to eq 107
      expect(extension.key_share_entry[0].group).to eq NamedGroup::X25519
      expect(extension.key_share_entry[0].key_exchange).to eq public_key_x25519
      expect(extension.key_share_entry[1].group).to eq NamedGroup::SECP256R1
      expect(extension.key_share_entry[1].key_exchange)
        .to eq public_key_secp256r1
      expect(extension.serialize).to eq ExtensionType::KEY_SHARE \
                                        + i2uint16(107) \
                                        + i2uint16(105) \
                                        + NamedGroup::X25519 \
                                        + i2uint16(32) \
                                        + public_key_x25519 \
                                        + NamedGroup::SECP256R1 \
                                        + i2uint16(65) \
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

    it 'should generate valid key_share' do
      expect(extension.msg_type).to eq HandshakeType::CLIENT_HELLO
      expect(extension.extension_type).to eq ExtensionType::KEY_SHARE
      expect(extension.length).to eq 2
      expect(extension.key_share_entry).to be_empty
      expect(extension.serialize).to eq ExtensionType::KEY_SHARE \
                                        + i2uint16(2) \
                                        + i2uint16(0)
    end
  end

  context 'valid key_share (KeyShareServerHello)' do
    let(:extension) do
      KeyShare.new(
        msg_type: HandshakeType::SERVER_HELLO,
        key_share_entry: [
          KeyShareEntry.new(
            group: NamedGroup::X25519,
            key_exchange: OpenSSL::Random.random_bytes(32).unpack('C*')
          )
        ]
      )
    end
    # TODO
  end

  context 'valid key_share (KeyShareHelloRetryRequest)' do
    let(:extension) do
      KeyShare.new(
        msg_type: HandshakeType::HELLO_RETRY_REQUEST,
        key_share_entry: [
          KeyShareEntry.new(
            group: NamedGroup::X25519,
            key_exchange: nil
          )
        ]
      )
    end
    # TODO
  end

  context 'valid key_share binary' do
    let(:extension) do
      KeyShare.deserialize(TESTBINARY_KEY_SHARE, HandshakeType::CLIENT_HELLO)
    end

    it 'should generate valid key_share' do
      expect(extension.extension_type).to eq ExtensionType::KEY_SHARE
      expect(extension.length).to eq 38
      expect(extension.key_share_entry[0].group).to eq NamedGroup::X25519
    end
  end
end
