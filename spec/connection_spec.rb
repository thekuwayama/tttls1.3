# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Connection do
  context '.verify_certificate_verify function' do
    let(:connection) do
      Connection.new
    end

    let(:certificate) do
      Certificate.deserialize(TESTBINARY_CERTIFICATE)
    end

    let(:certificate_verify) do
      CertificateVerify.deserialize(TESTBINARY_CERTIFICATE_VERIFY)
    end

    let(:transcript) do
      TESTBINARY_CLIENT_HELLO \
      + TESTBINARY_SERVER_HELLO \
      + TESTBINARY_ENCRYPTED_EXTENSIONS \
      + certificate.serialize
    end

    it 'should verify CertificateVerify.signature' do
      certificate_pem = certificate.certificate_list.first.cert_data.to_pem
      signature_scheme = certificate_verify.signature_scheme
      signature = certificate_verify.signature
      expect(connection.verify_certificate_verify(
               signature_scheme: signature_scheme,
               certificate_pem: certificate_pem,
               signature: signature,
               transcript: transcript
             )).to be true
    end
  end

  context '.sign_finished function' do
    let(:connection) do
      Connection.new
    end

    let(:client_finished) do
      Finished.deserialize(TESTBINARY_CLIENT_FINISHED, 32)
    end

    let(:finished_key) do
      TESTBINARY_CLIENT_FINISHED_KEY
    end

    let(:transcript) do
      TESTBINARY_CLIENT_HELLO \
      + TESTBINARY_SERVER_HELLO \
      + TESTBINARY_ENCRYPTED_EXTENSIONS \
      + TESTBINARY_CERTIFICATE \
      + TESTBINARY_CERTIFICATE_VERIFY \
      + TESTBINARY_SERVER_FINISHED
    end

    it 'should sign Client Finished.verify_data' do
      expect(connection.sign_finished(
               signature_scheme: SignatureScheme::RSA_PSS_RSAE_SHA256,
               finished_key: finished_key,
               transcript: transcript
             )).to eq client_finished.verify_data
    end
  end
end
