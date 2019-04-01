# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'
using Refinements

RSpec.describe TLS13::Refinements do
  context '0' do
    let(:integer) do
      0
    end

    it 'should return uint8' do
      expect(integer.to_uint8).to eq "\x00"
    end

    it 'should return uint16' do
      expect(integer.to_uint16).to eq "\x00\x00"
    end

    it 'should return uint24' do
      expect(integer.to_uint24).to eq "\x00\x00\x00"
    end

    it 'should return uint32' do
      expect(integer.to_uint32).to eq "\x00\x00\x00\x00"
    end

    it 'should return uint64' do
      expect(integer.to_uint64).to eq "\x00\x00\x00\x00\x00"
    end
  end

  context '-1' do
    let(:integer) do
      -1
    end

    it 'should not return uint8' do
      expect { integer.to_uint8 }.to raise_error(InternalError)
    end

    it 'should not return uint16' do
      expect { integer.to_uint16 }.to raise_error(InternalError)
    end

    it 'should not return uint24' do
      expect { integer.to_uint24 }.to raise_error(InternalError)
    end

    it 'should not return uint32' do
      expect { integer.to_uint32 }.to raise_error(InternalError)
    end

    it 'should not return uint64' do
      expect { integer.to_uint64 }.to raise_error(InternalError)
    end
  end

  context '1 << 8' do
    let(:integer) do
      1 << 8
    end

    it 'should not return uint8' do
      expect { integer.to_uint8 }.to raise_error(InternalError)
    end

    it 'should return uint16' do
      expect(integer.to_uint16).to eq "\x01\x00"
    end

    it 'should return uint24' do
      expect(integer.to_uint24).to eq "\x00\x01\x00"
    end

    it 'should return uint32' do
      expect(integer.to_uint32).to eq "\x00\x00\x01\x00"
    end

    it 'should return uint64' do
      expect(integer.to_uint64).to eq "\x00\x00\x00\x01\x00"
    end
  end

  context '1 << 16' do
    let(:integer) do
      1 << 16
    end

    it 'should not return uint8' do
      expect { integer.to_uint8 }.to raise_error(InternalError)
    end

    it 'should not return uint16' do
      expect { integer.to_uint16 }.to raise_error(InternalError)
    end

    it 'should return uint24' do
      expect(integer.to_uint24).to eq "\x01\x00\x00"
    end

    it 'should return uint32' do
      expect(integer.to_uint32).to eq "\x00\x01\x00\x00"
    end

    it 'should return uint64' do
      expect(integer.to_uint64).to eq "\x00\x00\x01\x00\x00"
    end
  end

  context '1 << 24' do
    let(:integer) do
      1 << 24
    end

    it 'should not return uint8' do
      expect { integer.to_uint8 }.to raise_error(InternalError)
    end

    it 'should not return uint16' do
      expect { integer.to_uint16 }.to raise_error(InternalError)
    end

    it 'should not return uint24' do
      expect { integer.to_uint24 }.to raise_error(InternalError)
    end

    it 'should return uint32' do
      expect(integer.to_uint32).to eq "\x01\x00\x00\x00"
    end

    it 'should return uint64' do
      expect(integer.to_uint64).to eq "\x00\x01\x00\x00\x00"
    end
  end

  context '1 << 32' do
    let(:integer) do
      1 << 32
    end

    it 'should not return uint8' do
      expect { integer.to_uint8 }.to raise_error(InternalError)
    end

    it 'should not return uint16' do
      expect { integer.to_uint16 }.to raise_error(InternalError)
    end

    it 'should not return uint24' do
      expect { integer.to_uint24 }.to raise_error(InternalError)
    end

    it 'should not return uint32' do
      expect { integer.to_uint32 }.to raise_error(InternalError)
    end

    it 'should return uint64' do
      expect(integer.to_uint64).to eq "\x01\x00\x00\x00\x00"
    end
  end

  context '1 << 64' do
    let(:integer) do
      1 << 64
    end

    it 'should not return uint8' do
      expect { integer.to_uint8 }.to raise_error(InternalError)
    end

    it 'should not return uint16' do
      expect { integer.to_uint16 }.to raise_error(InternalError)
    end

    it 'should not return uint24' do
      expect { integer.to_uint24 }.to raise_error(InternalError)
    end

    it 'should not return uint32' do
      expect { integer.to_uint32 }.to raise_error(InternalError)
    end

    it 'should not return uint64' do
      expect { integer.to_uint64 }.to raise_error(InternalError)
    end
  end

  context 'string' do
    let(:string) do
      'string'
    end

    it 'should be prefixed' do
      expect(string.prefix_uint8_length).to eq "\x06string"
      expect(string.prefix_uint16_length).to eq "\x00\x06string"
      expect(string.prefix_uint24_length).to eq "\x00\x00\x06string"
      expect(string.prefix_uint32_length).to eq "\x00\x00\x00\x06string"
      expect(string.prefix_uint64_length).to eq "\x00\x00\x00\x00\x06string"
    end
  end
end

RSpec.describe Convert do
  context 'binary' do
    let(:binary) do
      "\x01\x23\x45\x67\x89"
    end

    it 'should be converted to integer' do
      expect(Convert.bin2i(binary)).to eq 4_886_718_345
    end
  end
end
