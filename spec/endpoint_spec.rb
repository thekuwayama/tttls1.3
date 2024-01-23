# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'spec_helper'

RSpec.describe Endpoint do
  context 'endpoint, Simple 1-RTT Handshake,' do
    let(:key) do
      n = OpenSSL::BN.new(TESTBINARY_PKEY_MODULUS, 2)
      e = OpenSSL::BN.new(TESTBINARY_PKEY_PUBLIC_EXPONENT, 2)
      d = OpenSSL::BN.new(TESTBINARY_PKEY_PRIVATE_EXPONENT, 2)
      p = OpenSSL::BN.new(TESTBINARY_PKEY_PRIME1, 2)
      q = OpenSSL::BN.new(TESTBINARY_PKEY_PRIME2, 2)
      dmp1 = d % (p - 1.to_bn)
      dmq1 = d % (q - 1.to_bn)
      iqmp = q**-1.to_bn % p
      asn1 = OpenSSL::ASN1::Sequence(
        [
          OpenSSL::ASN1::Integer(0),
          OpenSSL::ASN1::Integer(n),
          OpenSSL::ASN1::Integer(e),
          OpenSSL::ASN1::Integer(d),
          OpenSSL::ASN1::Integer(p),
          OpenSSL::ASN1::Integer(q),
          OpenSSL::ASN1::Integer(dmp1),
          OpenSSL::ASN1::Integer(dmq1),
          OpenSSL::ASN1::Integer(iqmp)
        ]
      )
      OpenSSL::PKey::RSA.new(asn1)
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

    let(:transcript) do
      ch = ClientHello.deserialize(TESTBINARY_CLIENT_HELLO)
      sh = ServerHello.deserialize(TESTBINARY_SERVER_HELLO)
      ee = EncryptedExtensions.deserialize(TESTBINARY_ENCRYPTED_EXTENSIONS)
      transcript = Transcript.new
      transcript.merge!(
        CH => [ch, TESTBINARY_CLIENT_HELLO],
        SH => [sh, TESTBINARY_SERVER_HELLO],
        EE => [ee, TESTBINARY_ENCRYPTED_EXTENSIONS],
        CT => [ct, TESTBINARY_CERTIFICATE],
        CV => [cv, TESTBINARY_CERTIFICATE_VERIFY],
        CF => [cf, TESTBINARY_CLIENT_FINISHED],
        SF => [sf, TESTBINARY_SERVER_FINISHED]
      )
    end

    let(:digest) do
      CipherSuite.digest(CipherSuite::TLS_AES_128_GCM_SHA256)
    end

    it 'should verify server CertificateVerify.signature' do
      public_key = ct.certificate_list.first.cert_data.public_key
      signature_scheme = cv.signature_scheme
      signature = cv.signature

      expect(Endpoint.verified_certificate_verify?(
               public_key: public_key,
               signature_scheme: signature_scheme,
               signature: signature,
               context: 'TLS 1.3, server CertificateVerify',
               hash: transcript.hash(digest, CT)
             )).to be true
    end

    it 'should sign client Finished.verify_data' do
      expect(Endpoint.sign_finished(
               digest: 'SHA256',
               finished_key: TESTBINARY_CLIENT_FINISHED_KEY,
               hash: transcript.hash(digest, EOED)
             )).to eq cf.verify_data
    end

    it 'should verify server Finished.verify_data' do
      expect(Endpoint.verified_finished?(
               finished: sf,
               digest: 'SHA256',
               finished_key: TESTBINARY_SERVER_FINISHED_KEY,
               hash: transcript.hash(digest, CV)
             )).to be true
    end

    it 'should sign server CertificateVerify.signature' do
      public_key = ct.certificate_list.first.cert_data.public_key
      signature_scheme = cv.signature_scheme

      # used RSASSA-PSS signature_scheme, salt is a random sequence.
      # CertificateVerify.signature is random.
      signature = Endpoint.sign_certificate_verify(
        key: key,
        signature_scheme: signature_scheme,
        context: 'TLS 1.3, server CertificateVerify',
        hash: transcript.hash(digest, CT)
      )
      expect(Endpoint.verified_certificate_verify?(
               public_key: public_key,
               signature_scheme: signature_scheme,
               signature: signature,
               context: 'TLS 1.3, server CertificateVerify',
               hash: transcript.hash(digest, CT)
             )).to be true
    end
  end

  context 'endpoint, HelloRetryRequest,' do
    let(:ct) do
      Certificate.deserialize(TESTBINARY_HRR_CERTIFICATE)
    end

    let(:cv) do
      CertificateVerify.deserialize(TESTBINARY_HRR_CERTIFICATE_VERIFY)
    end

    let(:transcript) do
      ch1 = ClientHello.deserialize(TESTBINARY_HRR_CLIENT_HELLO1)
      hrr = ServerHello.deserialize(TESTBINARY_HRR_HELLO_RETRY_REQUEST)
      ch = ClientHello.deserialize(TESTBINARY_HRR_CLIENT_HELLO)
      sh = ServerHello.deserialize(TESTBINARY_HRR_SERVER_HELLO)
      ee = EncryptedExtensions.deserialize(TESTBINARY_HRR_ENCRYPTED_EXTENSIONS)
      transcript = Transcript.new
      transcript.merge!(
        CH1 => [ch1, TESTBINARY_HRR_CLIENT_HELLO1],
        HRR => [hrr, TESTBINARY_HRR_HELLO_RETRY_REQUEST],
        CH => [ch, TESTBINARY_HRR_CLIENT_HELLO],
        SH => [sh, TESTBINARY_HRR_SERVER_HELLO],
        EE => [ee, TESTBINARY_HRR_ENCRYPTED_EXTENSIONS],
        CT => [ct, TESTBINARY_HRR_CERTIFICATE],
        CV => [cv, TESTBINARY_HRR_CERTIFICATE_VERIFY]
      )
    end

    let(:digest) do
      CipherSuite.digest(CipherSuite::TLS_AES_128_GCM_SHA256)
    end

    it 'should verify server CertificateVerify.signature' do
      public_key = ct.certificate_list.first.cert_data.public_key
      signature_scheme = cv.signature_scheme
      signature = cv.signature

      expect(Endpoint.verified_certificate_verify?(
               public_key: public_key,
               signature_scheme: signature_scheme,
               signature: signature,
               context: 'TLS 1.3, server CertificateVerify',
               hash: transcript.hash(digest, CT)
             )).to be true
    end
  end
end
