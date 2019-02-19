require 'spec_helper'

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
        SignatureScheme::RSA_PKCS1_SHA512,
        SignatureScheme::RSA_PKCS1_SHA1
      ]
    end

    let(:extension) do
      SignatureAlgorithmsCert.new(
        supported_signature_algorithms: supported_signature_algorithms
      )
    end

    it 'should generate valid signature_algorithms' do
      expect(extension.extension_type)
        .to eq ExtensionType::SIGNATURE_ALGORITHMS_CERT
      expect(extension.length).to eq 20
      expect(extension.supported_signature_algorithms)
        .to eq supported_signature_algorithms
      expect(extension.serialize)
        .to eq ExtensionType::SIGNATURE_ALGORITHMS_CERT \
               + i2uint16(20) \
               + i2uint16(18) \
               + supported_signature_algorithms.flatten
    end
  end

  context 'valid signature_algorithms binary' do
    let(:extension) do
      SignatureAlgorithmsCert.deserialize(TESTBINARY_SIGNATURE_ALGORITHMS)
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

    it 'should generate valid signature_algorithms' do
      expect(extension.extension_type)
        .to eq ExtensionType::SIGNATURE_ALGORITHMS_CERT
      expect(extension.length).to eq 20
      expect(extension.supported_signature_algorithms)
        .to eq supported_signature_algorithms
    end
  end
end
