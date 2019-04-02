# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'
using Refinements

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
      expect(extension.cookie).to eq cookie
    end

    it 'should be serialized' do
      expect(extension.serialize).to eq ExtensionType::COOKIE \
                                        + (2**16 - 1).to_uint16 \
                                        + (2**16 - 3).to_uint16 \
                                        + cookie
    end
  end

  context 'ignored cookie, empty,' do
    let(:extension) do
      Cookie.new('')
    end

    it 'should be generated' do
      expect(extension.extension_type).to eq ExtensionType::COOKIE
      expect(extension.cookie).to eq ''
    end
  end

  context 'ignored cookie, nil,' do
    let(:extension) do
      Cookie.new(nil)
    end

    it 'should not be generated' do
      expect(extension.extension_type).to eq ExtensionType::COOKIE
      expect(extension.cookie).to eq ''
    end
  end

  context 'invalid cookie, too long,' do
    let(:extension) do
      Cookie.new('a' * (2**16 - 2))
    end

    it 'should not be generated' do
      expect { extension }.to raise_error(InternalError)
    end
  end

  context 'valid cookie binary' do
    let(:extension) do
      Cookie.deserialize(TESTBINARY_COOKIE)
    end

    it 'should generate object' do
      expect(extension.extension_type).to eq ExtensionType::COOKIE
      expect(extension.cookie).to eq TESTBINARY_COOKIE[2..]
    end

    it 'should generate serializable object' do
      expect(extension.serialize).to eq ExtensionType::COOKIE \
                                        + TESTBINARY_COOKIE.prefix_uint16_length
    end
  end

  context 'cookie binary, empty,' do
    let(:extension) do
      Cookie.deserialize("\x00\x00")
    end

    it 'should generat object' do
      expect(extension.extension_type).to eq ExtensionType::COOKIE
      expect(extension.cookie).to eq ''
    end
  end

  context 'invalid cookie binary, malformed binary,' do
    let(:extension) do
      Cookie.deserialize(TESTBINARY_COOKIE[0...-1])
    end

    it 'should generat UknownExtension object' do
      expect(extension.extension_type).to eq ExtensionType::COOKIE
      expect(extension.extension_data).to eq TESTBINARY_COOKIE[0...-1]
    end
  end
end
