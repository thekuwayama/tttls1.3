# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Extensions do
  context 'empty extensions' do
    let(:extensions) do
      Extensions.new
    end

    it 'should be generate' do
      expect(extensions).to be_empty
    end

    it 'should be serialize' do
      expect(extensions.serialize).to eq "\x00\x00"
    end
  end
end
