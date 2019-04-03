# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'
using Refinements

RSpec.describe CipherSuites do
  context 'default cipher suites' do
    let(:cs) do
      CipherSuites.new
    end

    it 'should be generated' do
      expect(cs).to eq DEFAULT_CIPHER_SUITES
    end

    it 'should be serialized' do
      expect(cs.serialize).to eq DEFAULT_CIPHER_SUITES.join.prefix_uint16_length
    end
  end

  context 'valid cipher suites binary' do
    let(:cs) do
      CipherSuites.deserialize(TESTBINARY_CIPHER_SUITES)
    end

    it 'should generate valid object' do
      expect(cs).to eq [CipherSuite::TLS_AES_256_GCM_SHA384,
                        CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
                        CipherSuite::TLS_AES_128_GCM_SHA256]
    end
  end

  context 'invalid cipher suites binary, too short' do
    let(:cs) do
      CipherSuites.deserialize(TESTBINARY_CIPHER_SUITES[0...-1])
    end

    it 'should not generate object' do
      expect { cs }.to raise_error(TLSError)
    end
  end

  context 'invalid cipher suites binary, binary is nil' do
    let(:cs) do
      CipherSuites.deserialize(nil)
    end

    it 'should not generate object' do
      expect { cs }.to raise_error(TLSError)
    end
  end
end
