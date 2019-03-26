# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe ChangeCipherSpec do
  context 'change_cipher_spec' do
    let(:message) do
      ChangeCipherSpec.new
    end

    it 'should be serialized' do
      expect(message.serialize).to eq "\x01"
    end
  end

  context 'valid change_cipher_spec binary' do
    let(:message) do
      ChangeCipherSpec.deserialize(TESTBINARY_CHANGE_CIPHER_SPEC)
    end

    it 'should generate valid serializable object' do
      expect(message.serialize).to eq "\x01"
    end
  end
end
