# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'spec_helper'
using Refinements

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
        SignatureScheme::RSA_PKCS1_SHA512
      ]
    end

    let(:extension) do
      SignatureAlgorithms.new(supported_signature_algorithms)
    end

    it 'should be generated' do
      expect(extension).to be_a(SignatureAlgorithms)

      expect(extension.extension_type).to eq ExtensionType::SIGNATURE_ALGORITHMS
      expect(extension.supported_signature_algorithms)
        .to eq supported_signature_algorithms
    end

    it 'should be serialized' do
      expect(extension.serialize).to eq ExtensionType::SIGNATURE_ALGORITHMS \
                                        + 18.to_uint16 \
                                        + 16.to_uint16 \
                                        + supported_signature_algorithms.join
    end
  end

  context 'invalid signature_algorithms, empty,' do
    let(:extension) do
      SignatureAlgorithms.new([])
    end

    it 'should not be generated' do
      expect { extension }.to raise_error(ErrorAlerts)
    end
  end

  context 'invalid signature_algorithms, too long,' do
    let(:extension) do
      SignatureAlgorithms.new((0..2**15 - 2).to_a.map(&:to_uint16))
    end

    it 'should not be generated' do
      expect { extension }.to raise_error(ErrorAlerts)
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
        SignatureScheme::RSA_PKCS1_SHA512
      ]
    end

    it 'should generate valid object' do
      expect(extension).to be_a(SignatureAlgorithms)

      expect(extension.extension_type).to eq ExtensionType::SIGNATURE_ALGORITHMS
      expect(extension.supported_signature_algorithms)
        .to eq supported_signature_algorithms
    end

    it 'should generate serializable object' do
      expect(extension.serialize)
        .to eq ExtensionType::SIGNATURE_ALGORITHMS \
               + TESTBINARY_SIGNATURE_ALGORITHMS.prefix_uint16_length
    end
  end

  context 'invalid signature_algorithms binary, malformed binary,' do
    let(:extension) do
      SignatureAlgorithms.deserialize(TESTBINARY_SIGNATURE_ALGORITHMS[0...-1])
    end

    it 'should return nil' do
      expect(extension).to be nil
    end
  end
end
