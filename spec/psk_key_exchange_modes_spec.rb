require 'spec_helper'

RSpec.describe PskKeyExchangeModes do
  context 'valid psk_key_exchange_modes' do
    let(:extension) do
      PskKeyExchangeModes.new(
        ke_modes: [
          PskKeyExchangeMode::PSK_KE,
          PskKeyExchangeMode::PSK_DHE_KE
        ]
      )
    end

    it 'should generate valid psk_key_exchange_modes' do
      expect(extension.extension_type)
        .to eq ExtensionType::PSK_KEY_EXCHANGE_MODES
      expect(extension.length).to eq 3
      expect(extension.ke_modes).to eq [PskKeyExchangeMode::PSK_KE,
                                        PskKeyExchangeMode::PSK_DHE_KE]
      expect(extension.serialize).to eq [0x00, 0x2d, 0x00, 0x03, 0x02, 0x00,
                                         0x01]
    end
  end

  context 'valid psk_key_exchange_modes binary' do
    let(:extension) do
      PskKeyExchangeModes.deserialize(TESTBINARY_PSK_KEY_EXCHANGE_MODES)
    end

    it 'should generate valid psk_key_exchange_modes' do
      expect(extension.extension_type)
        .to eq ExtensionType::PSK_KEY_EXCHANGE_MODES
      expect(extension.length).to eq 3
      expect(extension.ke_modes).to eq [PskKeyExchangeMode::PSK_KE,
                                        PskKeyExchangeMode::PSK_DHE_KE]
    end
  end
end
