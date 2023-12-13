# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'spec_helper'
using Refinements

RSpec.describe ECHClientHello do
  context 'valid ech binary' do
    let(:extension) do
      ECHClientHello.deserialize(TESTBINARY_ECH_CHO, ECHClientHelloType::OUTER)
    end

    it 'should generate valid object' do
    end
  end
end
