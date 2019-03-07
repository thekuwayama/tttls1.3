# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PskKeyExchangeModes do
  context 'valid psk_key_exchange_modes' do
    let(:extension) do
      PskKeyExchangeModes.new([PskKeyExchangeMode::PSK_KE,
                               PskKeyExchangeMode::PSK_DHE_KE])
    end

    it 'should generate valid psk_key_exchange_modes' do
      expect(extension.extension_type)
        .to eq ExtensionType::PSK_KEY_EXCHANGE_MODES
      expect(extension.length).to eq 3
      expect(extension.ke_modes).to eq [PskKeyExchangeMode::PSK_KE,
                                        PskKeyExchangeMode::PSK_DHE_KE]
      expect(extension.serialize).to eq ExtensionType::PSK_KEY_EXCHANGE_MODES \
                                        + i2uint16(3) \
                                        + i2uint8(2) \
                                        + [PskKeyExchangeMode::PSK_KE,
                                           PskKeyExchangeMode::PSK_DHE_KE].join
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
