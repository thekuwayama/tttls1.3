# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Alert do
  context 'unexpected_message alert' do
    let(:message) do
      Alert.new(level: AlertLevel::FATAL,
                description: ALERT_DESCRIPTION[:unexpected_message])
    end

    it 'should be serialized' do
      expect(message.serialize).to eq AlertLevel::FATAL \
                                      + ALERT_DESCRIPTION[:unexpected_message]
    end

    it 'should return error' do
      expect(message.to_error).to be_a_kind_of(ErrorAlerts)
      expect(message.to_error.message).to eq 'unexpected_message'
    end
  end

  context 'unexpected_message alert, not given level' do
    let(:message) do
      Alert.new(description: ALERT_DESCRIPTION[:unexpected_message])
    end

    it 'should be serialized' do
      expect(message.serialize).to eq AlertLevel::FATAL \
                                      + ALERT_DESCRIPTION[:unexpected_message]
    end

    it 'should return error' do
      expect(message.to_error).to be_a_kind_of(ErrorAlerts)
      expect(message.to_error.message).to eq 'unexpected_message'
    end
  end

  context 'valid alert binary' do
    let(:message) do
      Alert.deserialize(TESTBINARY_ALERT)
    end

    it 'should generate object' do
      expect(message.level).to eq AlertLevel::WARNING
      expect(message.description).to eq ALERT_DESCRIPTION[:close_notify]
    end

    it 'should generate serializable object' do
      expect(message.serialize).to eq TESTBINARY_ALERT
    end
  end
end
