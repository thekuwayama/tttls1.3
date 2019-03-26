# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe CipherSuites do
  context 'default cipher suites' do
    let(:cs) do
      CipherSuites.new
    end

    it 'should be generated' do
      expect(cs).to eq DEFALT_CIPHER_SUITES
    end

    it 'should be serialized' do
      expect(cs.serialize).to eq i2uint16(DEFALT_CIPHER_SUITES.length * 2) \
                                 + DEFALT_CIPHER_SUITES.join
    end
  end

  context 'valid cipher suites binary' do
    let(:cs) do
      CipherSuites.deserialize(TESTBINARY_CIPHER_SUITES)
    end

    it 'should generate valid object' do
      expect(cs).to eq DEFALT_CIPHER_SUITES
    end
  end

  context 'invalid cipher suites binary, too short' do
    let(:cs) do
      CipherSuites.deserialize(TESTBINARY_CIPHER_SUITES[0...-1])
    end

    it 'should not generate object' do
      expect { cs }.to raise_error(RuntimeError)
    end
  end

  context 'invalid cipher suites binary, binary is nil' do
    let(:cs) do
      CipherSuites.deserialize(nil)
    end

    it 'should not generate object' do
      expect { cs }.to raise_error(RuntimeError)
    end
  end
end
