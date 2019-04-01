# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe TLSError do
  let(:error) do
    TLSError.new('unexpected_message')
  end

  let(:alert) do
    Alert.new(description: ALERT_DESCRIPTION[:unexpected_message])
  end

  it 'should return alert' do
    expect(error.to_alert.serialize).to eq alert.serialize
  end
end
