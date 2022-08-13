# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'spec_helper'
using Refinements

RSpec.describe EndOfEarlyData do
  context 'end_of_early_data' do
    let(:message) do
      EndOfEarlyData.new
    end

    it 'should be serialized' do
      expect(message.serialize).to eq HandshakeType::END_OF_EARLY_DATA \
                                      + ''.prefix_uint24_length
    end
  end

  context 'valid end_of_early_data binary' do
    let(:message) do
      EndOfEarlyData.deserialize(TESTBINARY_0_RTT_END_OF_EARLY_DATA)
    end

    it 'should generate valid serializable object' do
      expect(message.serialize).to eq TESTBINARY_0_RTT_END_OF_EARLY_DATA
    end
  end
end
