# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Cookie do
  context 'valid cookie' do
    let(:cookie) do
      OpenSSL::Random.random_bytes(2**16 - 3)
    end

    let(:extension) do
      Cookie.new(cookie)
    end

    it 'should be generated' do
      expect(extension.extension_type).to eq ExtensionType::COOKIE
      expect(extension.length).to eq 2 + (2**16 - 3)
      expect(extension.cookie).to eq cookie
    end

    it 'should be serialized' do
      expect(extension.serialize).to eq ExtensionType::COOKIE \
                                        + i2uint16(2**16 - 1) \
                                        + i2uint16(2**16 - 3) \
                                        + cookie
    end
  end

  context 'invalid cookie, empty,' do
    let(:extension) do
      Cookie.new('')
    end

    it 'should not be generated' do
      expect { extension }.to raise_error(RuntimeError)
    end
  end

  context 'invalid cookie, nil,' do
    let(:extension) do
      Cookie.new(nil)
    end

    it 'should not be generated' do
      expect { extension }.to raise_error(RuntimeError)
    end
  end

  context 'invalid cookie, too long,' do
    let(:extension) do
      Cookie.new('a' * (2**16 - 2))
    end

    it 'should not be generated' do
      expect { extension }.to raise_error(RuntimeError)
    end
  end

  context 'valid cookie binary' do
    let(:extension) do
      Cookie.deserialize(TESTBINARY_COOKIE)
    end

    it 'should generate object' do
      expect(extension.extension_type).to eq ExtensionType::COOKIE
      expect(extension.length).to eq TESTBINARY_COOKIE.length
      expect(extension.cookie).to eq TESTBINARY_COOKIE[2..-1]
    end
  end

  context 'invalid cookie binary, empty,' do
    let(:extension) do
      Cookie.deserialize("\x00\x00")
    end

    it 'should not generat object' do
      expect { extension }.to raise_error(RuntimeError)
    end
  end

  context 'invalid cookie binary, malformed binary,' do
    let(:extension) do
      Cookie.deserialize(TESTBINARY_COOKIE[0...-1])
    end

    it 'should not generat object' do
      expect { extension }.to raise_error(RuntimeError)
    end
  end
end
