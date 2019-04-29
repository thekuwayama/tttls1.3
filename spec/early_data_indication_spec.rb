# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'spec_helper'
using Refinements

RSpec.describe EarlyDataIndication do
  context 'valid early_data_indication, NewSessionTicket,' do
    let(:extension) do
      EarlyDataIndication.new(2**32 - 1)
    end

    it 'should be generated' do
      expect(extension.extension_type).to eq ExtensionType::EARLY_DATA
      expect(extension.max_early_data_size).to eq 2**32 - 1
    end

    it 'should be serialized' do
      expect(extension.serialize).to eq ExtensionType::EARLY_DATA \
                                        + 4.to_uint16 \
                                        + (2**32 - 1).to_uint32
    end
  end

  context 'valid early_data_indication, ClientHello or EncryptedExtensions,' do
    let(:extension) do
      EarlyDataIndication.new(nil)
    end

    it 'should be generated' do
      expect(extension.extension_type).to eq ExtensionType::EARLY_DATA
      expect(extension.max_early_data_size).to be nil
    end

    it 'should be serialized' do
      expect(extension.serialize).to eq ExtensionType::EARLY_DATA \
                                        + 0.to_uint16
    end
  end

  context 'valid early_data_indication binary, NewSessionTicket,' do
    let(:extension) do
      EarlyDataIndication.deserialize(TESTBINARY_EARLY_DATA_INDICATION_NST,
                                      HandshakeType::NEW_SESSION_TICKET)
    end

    it 'should generate valid object' do
      expect(extension.extension_type).to eq ExtensionType::EARLY_DATA
      expect(extension.max_early_data_size).to eq 1024
    end
  end

  context 'valid early_data_indication binary, ClientHello,' do
    let(:extension) do
      EarlyDataIndication.deserialize(TESTBINARY_EARLY_DATA_INDICATION_CH,
                                      HandshakeType::CLIENT_HELLO)
    end

    it 'should generate valid object' do
      expect(extension.extension_type).to eq ExtensionType::EARLY_DATA
      expect(extension.max_early_data_size).to be nil
    end
  end
end
