# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'
using Refinements

RSpec.describe SignatureAlgorithmsCert do
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
      SignatureAlgorithmsCert.new(supported_signature_algorithms)
    end

    it 'should be generated' do
      expect(extension.extension_type)
        .to eq ExtensionType::SIGNATURE_ALGORITHMS_CERT
      expect(extension.supported_signature_algorithms)
        .to eq supported_signature_algorithms
    end

    it 'should be serialized' do
      expect(extension.serialize)
        .to eq ExtensionType::SIGNATURE_ALGORITHMS_CERT \
               + 18.to_uint16 \
               + 16.to_uint16 \
               + supported_signature_algorithms.join
    end
  end

  context 'valid signature_algorithms binary' do
    let(:extension) do
      SignatureAlgorithmsCert.deserialize(TESTBINARY_SIGNATURE_ALGORITHMS_CERT)
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
      expect(extension.extension_type)
        .to eq ExtensionType::SIGNATURE_ALGORITHMS_CERT
      expect(extension.supported_signature_algorithms)
        .to eq supported_signature_algorithms
    end

    it 'should generate serializable object' do
      expect(extension.serialize)
        .to eq ExtensionType::SIGNATURE_ALGORITHMS_CERT \
               + TESTBINARY_SIGNATURE_ALGORITHMS_CERT.prefix_uint16_length
    end
  end
end
