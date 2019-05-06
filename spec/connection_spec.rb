# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'spec_helper'

RSpec.describe Connection do
  context 'connection, Simple 1-RTT Handshake,' do
    let(:private_key) do
      rsa = OpenSSL::PKey::RSA.new
      rsa.set_key(OpenSSL::BN.new(TESTBINARY_PKEY_MODULUS, 2),
                  OpenSSL::BN.new(TESTBINARY_PKEY_PUBLIC_EXPONENT, 2),
                  OpenSSL::BN.new(TESTBINARY_PKEY_PRIVATE_EXPONENT, 2))
      rsa.set_factors(OpenSSL::BN.new(TESTBINARY_PKEY_PRIME1, 2),
                      OpenSSL::BN.new(TESTBINARY_PKEY_PRIME2, 2))
      rsa
    end

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
      public_key = ct.certificate_list.first.cert_data.public_key
      signature_scheme = cv.signature_scheme
      signature = cv.signature
      expect(connection.send(:do_verify_certificate_verify,
                             public_key: public_key,
                             signature_scheme: signature_scheme,
                             signature: signature,
                             context: 'TLS 1.3, server CertificateVerify',
                             handshake_context_end: CT))
        .to be true
    end

    it 'should sign client Finished.verify_data' do
      expect(connection.send(:do_sign_finished,
                             digest: 'SHA256',
                             finished_key: TESTBINARY_CLIENT_FINISHED_KEY,
                             handshake_context_end: EOED))
        .to eq cf.verify_data
    end

    it 'should verify server Finished.verify_data' do
      expect(connection.send(:do_verify_finished,
                             digest: 'SHA256',
                             finished_key: TESTBINARY_SERVER_FINISHED_KEY,
                             handshake_context_end: CV,
                             signature: sf.verify_data))
        .to be true
    end

    it 'should sign server CertificateVerify.signature' do
      public_key = ct.certificate_list.first.cert_data.public_key
      signature_scheme = cv.signature_scheme
      # NOTE:
      # used RSASSA-PSS signature_scheme, salt is a random sequence.
      # CertificateVerify.signature is random.
      signature = connection.send(:do_sign_certificate_verify,
                                  private_key: private_key,
                                  signature_scheme: signature_scheme,
                                  context: 'TLS 1.3, server CertificateVerify',
                                  handshake_context_end: CT)
      expect(connection.send(:do_verify_certificate_verify,
                             public_key: public_key,
                             signature_scheme: signature_scheme,
                             signature: signature,
                             context: 'TLS 1.3, server CertificateVerify',
                             handshake_context_end: CT))
        .to be true
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
      public_key = ct.certificate_list.first.cert_data.public_key
      signature_scheme = cv.signature_scheme
      signature = cv.signature
      expect(connection.send(:do_verify_certificate_verify,
                             public_key: public_key,
                             signature_scheme: signature_scheme,
                             signature: signature,
                             context: 'TLS 1.3, server CertificateVerify',
                             handshake_context_end: CT))
        .to be true
    end
  end
end
