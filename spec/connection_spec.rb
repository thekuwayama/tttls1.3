# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Connection do
  context 'connection, Simple 1-RTT Handshake,' do
    let(:ct) do
      Certificate.deserialize(TESTBINARY_CERTIFICATE)
    end

    let(:cv) do
      CertificateVerify.deserialize(TESTBINARY_CERTIFICATE_VERIFY)
    end

    let(:cf) do
      Finished.deserialize(TESTBINARY_CLIENT_FINISHED)
    end

    let(:sf) do
      Finished.deserialize(TESTBINARY_SERVER_FINISHED)
    end

    let(:connection) do
      connection = Connection.new(nil)
      transcript = Transcript.new
      transcript.merge!(
        CH => ClientHello.deserialize(TESTBINARY_CLIENT_HELLO),
        SH => ServerHello.deserialize(TESTBINARY_SERVER_HELLO),
        EE => EncryptedExtensions.deserialize(TESTBINARY_ENCRYPTED_EXTENSIONS),
        CT => ct,
        CV => cv,
        CF => cf,
        SF => sf
      )
      connection.instance_variable_set(:@transcript, transcript)
      connection.instance_variable_set(:@cipher_suite,
                                       CipherSuite::TLS_AES_128_GCM_SHA256)
      connection
    end

    it 'should verify server CertificateVerify.signature' do
      certificate_pem = ct.certificate_list.first.cert_data.to_pem
      signature_scheme = cv.signature_scheme
      signature = cv.signature
      expect(connection.send(:do_verify_certificate_verify,
                             certificate_pem: certificate_pem,
                             signature_scheme: signature_scheme,
                             signature: signature,
                             context: 'TLS 1.3, server CertificateVerify',
                             handshake_context_end: CT))
        .to be true
    end

    it 'should verify server Finished.verify_data' do
      expect(connection.send(:do_verify_finished,
                             digest: 'SHA256',
                             finished_key: TESTBINARY_SERVER_FINISHED_KEY,
                             handshake_context_end: CV,
                             signature: sf.verify_data))
        .to be true
    end

    it 'should sign client Finished.verify_data' do
      expect(connection.send(:do_sign_finished,
                             digest: 'SHA256',
                             finished_key: TESTBINARY_CLIENT_FINISHED_KEY,
                             handshake_context_end: EOED))
        .to eq cf.verify_data
    end
  end

  context 'connection, HelloRetryRequest,' do
    let(:ct) do
      Certificate.deserialize(TESTBINARY_HRR_CERTIFICATE)
    end

    let(:cv) do
      CertificateVerify.deserialize(TESTBINARY_HRR_CERTIFICATE_VERIFY)
    end

    let(:connection) do
      connection = Connection.new(nil)
      transcript = Transcript.new
      transcript.merge!(
        CH1 => ClientHello.deserialize(TESTBINARY_HRR_CLIENT_HELLO1),
        HRR => ServerHello.deserialize(TESTBINARY_HRR_HELLO_RETRY_REQUEST),
        CH => ClientHello.deserialize(TESTBINARY_HRR_CLIENT_HELLO),
        SH => ServerHello.deserialize(TESTBINARY_HRR_SERVER_HELLO),
        EE =>
        EncryptedExtensions.deserialize(TESTBINARY_HRR_ENCRYPTED_EXTENSIONS),
        CT => ct,
        CV => cv
      )
      connection.instance_variable_set(:@transcript, transcript)
      connection.instance_variable_set(:@cipher_suite,
                                       CipherSuite::TLS_AES_128_GCM_SHA256)
      connection
    end

    it 'should verify server CertificateVerify.signature' do
      certificate_pem = ct.certificate_list.first.cert_data.to_pem
      signature_scheme = cv.signature_scheme
      signature = cv.signature
      expect(connection.send(:do_verify_certificate_verify,
                             certificate_pem: certificate_pem,
                             signature_scheme: signature_scheme,
                             signature: signature,
                             context: 'TLS 1.3, server CertificateVerify',
                             handshake_context_end: CT))
        .to be true
    end
  end
end
