# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe ApplicationData do
  context 'application_data' do
    let(:message) do
      ApplicationData.new(TESTBINARY_CLIENT_APPLICATION_DATA)
    end

    it 'should be serialize' do
      expect(message.serialize).to eq TESTBINARY_CLIENT_APPLICATION_DATA
    end
  end

  context 'valid application_data binary' do
    let(:message) do
      ApplicationData.deserialize(TESTBINARY_CLIENT_APPLICATION_DATA)
    end

    it 'should generate valid serializable object' do
      expect(message.serialize).to eq TESTBINARY_CLIENT_APPLICATION_DATA
    end
  end
end
