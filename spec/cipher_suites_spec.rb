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

    it 'should serialize binary' do
      expect(cs.serialize).to eq [0x00, 0x06] + DEFALT_CIPHER_SUITES
    end
  end

  context 'deserialize' do
    # TODO
  end
end
