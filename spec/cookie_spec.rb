require 'spec_helper'

RSpec.describe Cookie do
  context 'valid cookie' do
    let(:cookie) do
      OpenSSL::Random.random_bytes(2**16 - 3).unpack('C*')
    end

    let(:extension) do
      Cookie.new(cookie: cookie)
    end

    it 'should generate valid cookie' do
      expect(extension.extension_type).to eq ExtensionType::COOKIE
      expect(extension.length).to eq 2 + (2**16 - 3)
      expect(extension.cookie).to eq cookie
      expect(extension.serialize).to eq ExtensionType::COOKIE \
                                        + i2uint16(2 + (2**16 - 3)) \
                                        + i2uint16(2**16 - 3) \
                                        + cookie
    end
  end

  context 'valid cookie binary' do
    let(:extension) do
      Cookie.deserialize(TESTBINARY_COOKIE)
    end

    it 'should generate valid cookie' do
      expect(extension.extension_type).to eq ExtensionType::COOKIE
      expect(extension.length).to eq TESTBINARY_COOKIE.length
      expect(extension.cookie).to eq TESTBINARY_COOKIE[2..-1]
    end
  end
end
