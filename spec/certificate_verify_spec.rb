# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'spec_helper'
using Refinements

RSpec.describe CertificateVerify do
  context 'valid certificate_verify' do
    let(:signature) do
      OpenSSL::Random.random_bytes(128)
    end

    let(:message) do
      CertificateVerify.new(
        signature_scheme: SignatureScheme::RSA_PSS_RSAE_SHA256,
        signature:
      )
    end

    it 'should be generated' do
      expect(message.msg_type).to eq HandshakeType::CERTIFICATE_VERIFY
      expect(message.signature_scheme) \
        .to eq SignatureScheme::RSA_PSS_RSAE_SHA256
      expect(message.signature).to eq signature
    end

    it 'should be serialized' do
      expect(message.serialize).to eq HandshakeType::CERTIFICATE_VERIFY \
                                      + 132.to_uint24 \
                                      + SignatureScheme::RSA_PSS_RSAE_SHA256 \
                                      + signature.prefix_uint16_length
    end
  end

  context 'valid certificate_verify binary' do
    let(:message) do
      CertificateVerify.deserialize(TESTBINARY_CERTIFICATE_VERIFY)
    end

    it 'should generate valid object' do
      expect(message.msg_type).to eq HandshakeType::CERTIFICATE_VERIFY
      expect(message.signature_scheme) \
        .to eq SignatureScheme::RSA_PSS_RSAE_SHA256
      expect(message.signature.length).to eq 128
    end

    it 'should generate serializable object' do
      expect(message.serialize).to eq TESTBINARY_CERTIFICATE_VERIFY
    end
  end
end
