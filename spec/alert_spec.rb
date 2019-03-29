# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Alert do
  context 'unexpected_message alert' do
    let(:message) do
      Alert.new(level: AlertLevel::FATAL,
                description: AlertDescription::UNEXPECTED_MESSAGE)
    end

    it 'should be serialized' do
      expect(message.serialize).to eq AlertLevel::FATAL \
                                      + AlertDescription::UNEXPECTED_MESSAGE
    end
  end

  context 'valid alert binary' do
    let(:message) do
      Alert.deserialize(TESTBINARY_ALERT)
    end

    it 'should generate object' do
      expect(message.level).to eq AlertLevel::WARNING
      expect(message.description).to eq AlertDescription::CLOSE_NOTIFY
    end

    it 'should generate serializable object' do
      expect(message.serialize).to eq TESTBINARY_ALERT
    end
  end
end
