# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe ClientHello do
  context 'serialize' do
    # TODO
  end

  context 'deserialize' do
    let(:message) do
      ClientHello.deserialize(TESTBINARY_CLIENT_HELLO)
    end

    it 'should generate valid client hello' do
      expect(message.msg_type).to eq HandshakeType::CLIENT_HELLO
    end
  end
end
