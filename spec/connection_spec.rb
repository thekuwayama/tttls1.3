# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Connection do
  context 'connection' do
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
      ch = ClientHello.deserialize(TESTBINARY_CLIENT_HELLO)
      sh = ServerHello.deserialize(TESTBINARY_SERVER_HELLO)
      ee = EncryptedExtensions.deserialize(TESTBINARY_ENCRYPTED_EXTENSIONS)
      ch.serialize + sh.serialize + ee.serialize + certificate.serialize
    end

    it 'should verify signature of CertificateVerify' do
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
end
