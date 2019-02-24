require 'spec_helper'

RSpec.describe CipherSuites do
  context 'valid cipher suites' do
    let(:cs) do
      CipherSuites.new
    end

    it 'should generate default cipher suites' do
      expect(cs.length).to eq 6
      expect(cs.cipher_suites).to eq DEFALT_CIPHER_SUITES
    end

    it 'should serialize' do
      expect(cs.serialize).to eq ([0x00, 0x06] + DEFALT_CIPHER_SUITES).flatten
    end
  end

  context 'valid cipher suites binary' do
    let(:cs) do
      CipherSuites.deserialize(TESTBINARY_CIPHER_SUITES)
    end

    it 'should generate valid cipher suites' do
      expect(cs.length).to eq 6
      expect(cs.cipher_suites).to eq DEFALT_CIPHER_SUITES
    end
  end

  context 'invalid cipher suites binary, too short' do
    let(:cs) do
      CipherSuites.deserialize(TESTBINARY_CIPHER_SUITES[0...-1])
    end

    it 'should not generate cipher suites' do
      expect { cs }.to raise_error(RuntimeError)
    end
  end

  context 'invalid cipher suites binary, binary is nil' do
    let(:cs) do
      CipherSuites.deserialize(nil)
    end

    it 'should not generate cipher suites' do
      expect { cs }.to raise_error(RuntimeError)
    end
  end
end
