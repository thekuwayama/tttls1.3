# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'
using Refinements

RSpec.describe Alpn do
  context 'valid alpn' do
    let(:protocol_name_list) do
      ['h2', 'http/1.1', 'http/1.0']
    end

    let(:extension) do
      Alpn.new(protocol_name_list)
    end

    it 'should be generated' do
      expect(extension.extension_type)
        .to eq ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION
      expect(extension.protocol_name_list).to eq protocol_name_list
    end

    it 'should be serialized' do
      expect(extension.serialize)
        .to eq ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION \
               + 23.to_uint16 \
               + 21.to_uint16 \
               + 'h2'.prefix_uint8_length \
               + 'http/1.1'.prefix_uint8_length \
               + 'http/1.0'.prefix_uint8_length
    end
  end

  context 'invalid alpn, empty,' do
    let(:extension) do
      Alpn.new([])
    end

    it 'should not be generated' do
      expect { extension }.to raise_error(ErrorAlerts)
    end
  end

  context 'valid alpn binary' do
    let(:extension) do
      Alpn.deserialize(TESTBINARY_ALPN)
    end

    it 'should generate valid object' do
      expect(extension.extension_type)
        .to eq ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION
      expect(extension.protocol_name_list).to eq ['h2', 'http/1.1']
    end
  end
end
