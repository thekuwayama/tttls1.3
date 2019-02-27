# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe SignatureAlgorithms do
  context 'valid signature_algorithms' do
    let(:supported_signature_algorithms) do
      [
        SignatureScheme::ECDSA_SECP256R1_SHA256,
        SignatureScheme::RSA_PSS_RSAE_SHA256,
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::ECDSA_SECP384R1_SHA384,
        SignatureScheme::RSA_PSS_RSAE_SHA384,
        SignatureScheme::RSA_PKCS1_SHA384,
        SignatureScheme::RSA_PSS_RSAE_SHA512,
        SignatureScheme::RSA_PKCS1_SHA512,
        SignatureScheme::RSA_PKCS1_SHA1
      ]
    end

    let(:extension) do
      SignatureAlgorithms.new(supported_signature_algorithms)
    end

    it 'should be generated' do
      expect(extension.extension_type).to eq ExtensionType::SIGNATURE_ALGORITHMS
      expect(extension.length).to eq 20
      expect(extension.supported_signature_algorithms)
        .to eq supported_signature_algorithms
    end

    it 'should be serialized' do
      expect(extension.serialize).to eq ExtensionType::SIGNATURE_ALGORITHMS \
                                        + i2uint16(20) \
                                        + i2uint16(18) \
                                        + supported_signature_algorithms.join
    end
  end

  context 'invalid signature_algorithms, empty,' do
    let(:extension) do
      SignatureAlgorithms.new([])
    end

    it 'should not be generated' do
      expect { extension }.to raise_error(RuntimeError)
    end
  end

  context 'invalid signature_algorithms, too long,' do
    let(:extension) do
      SignatureAlgorithms.new((0..2**15 - 2).to_a.map { |x| i2uint16(x) })
    end

    it 'should not be generated' do
      expect { extension }.to raise_error(RuntimeError)
    end
  end

  context 'valid signature_algorithms binary' do
    let(:extension) do
      SignatureAlgorithms.deserialize(TESTBINARY_SIGNATURE_ALGORITHMS)
    end

    let(:supported_signature_algorithms) do
      [
        SignatureScheme::ECDSA_SECP256R1_SHA256,
        SignatureScheme::RSA_PSS_RSAE_SHA256,
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::ECDSA_SECP384R1_SHA384,
        SignatureScheme::RSA_PSS_RSAE_SHA384,
        SignatureScheme::RSA_PKCS1_SHA384,
        SignatureScheme::RSA_PSS_RSAE_SHA512,
        SignatureScheme::RSA_PKCS1_SHA512,
        SignatureScheme::RSA_PKCS1_SHA1
      ]
    end

    it 'should generate valid object' do
      expect(extension.extension_type).to eq ExtensionType::SIGNATURE_ALGORITHMS
      expect(extension.length).to eq 20
      expect(extension.supported_signature_algorithms)
        .to eq supported_signature_algorithms
    end
  end

  context 'invalid signature_algorithms binary, malformed binary,' do
    let(:extension) do
      SignatureAlgorithms.deserialize(TESTBINARY_SIGNATURE_ALGORITHMS[0...-1])
    end

    it 'should not generate object' do
      expect { extension }.to raise_error(RuntimeError)
    end
  end
end
