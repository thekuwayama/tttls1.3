# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'spec_helper'
using Refinements

RSpec.describe Alpn do
  context 'valid compress_certificate' do
    let(:algorithms) do
      [CertificateCompressionAlgorithm::ZLIB]
    end

    let(:extension) do
      CompressCertificate.new(algorithms)
    end

    it 'should be generated' do
      expect(extension.extension_type)
        .to eq ExtensionType::COMPRESS_CERTIFICATE
      expect(extension.algorithms).to eq algorithms
    end

    it 'should be serialized' do
      expect(extension.serialize)
        .to eq ExtensionType::COMPRESS_CERTIFICATE \
               + 3.to_uint16 \
               + 2.to_uint8 \
               + "\x00\x01"
    end
  end

  context 'invalid compress_certificate, empty,' do
    let(:extension) do
      CompressCertificate.new([])
    end

    it 'should not be generated' do
      expect { extension }.to raise_error(ErrorAlerts)
    end
  end

  context 'valid compress_certificate binary' do
    let(:extension) do
      CompressCertificate.deserialize(TESTBINARY_COMPRESS_CERTIFICATE)
    end

    it 'should generate valid object' do
      expect(extension.extension_type)
        .to eq ExtensionType::COMPRESS_CERTIFICATE
      expect(extension.algorithms)
        .to eq [CertificateCompressionAlgorithm::ZLIB]
    end
  end
end
