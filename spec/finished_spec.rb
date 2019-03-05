# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Finished do
  context 'valid finished' do
    let(:verify_data) do
      OpenSSL::Random.random_bytes(128)
    end

    let(:message) do
      Finished.new(verify_data)
    end

    it 'should be generated' do
      expect(message.msg_type).to eq HandshakeType::FINISHED
      expect(message.length).to eq 128
      expect(message.verify_data).to eq verify_data
    end

    it 'should be serialized' do
      expect(message.serialize).to eq HandshakeType::FINISHED \
                                      + i2uint24(message.length) \
                                      + verify_data
    end
  end

  context 'valid finished binary' do
    let(:message) do
      Finished.deserialize(TESTBINARY_FINISHED, 32)
    end

    it 'should generate valid object' do
      expect(message.msg_type).to eq HandshakeType::FINISHED
      expect(message.hash_length).to eq 32
    end
  end
end
