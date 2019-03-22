# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Connection do
  context 'connection' do
    let(:ct) do
      Certificate.deserialize(TESTBINARY_CERTIFICATE)
    end

    let(:cv) do
      CertificateVerify.deserialize(TESTBINARY_CERTIFICATE_VERIFY)
    end

    let(:connection) do
      connection = Connection.new(nil)
      transcript = {
        CH => ClientHello.deserialize(TESTBINARY_CLIENT_HELLO),
        SH => ServerHello.deserialize(TESTBINARY_SERVER_HELLO),
        EE => EncryptedExtensions.deserialize(TESTBINARY_ENCRYPTED_EXTENSIONS),
        CT => ct,
        CV => cv
      }
      connection.instance_variable_set(:@transcript, transcript)
      connection
    end

    it 'should verify server CertificateVerify.signature' do
      expect(connection.do_verify_certificate_verify(
               certificate_pem: ct.certificate_list.first.cert_data.to_pem,
               signature_scheme: cv.signature_scheme,
               signature: cv.signature,
               context: 'TLS 1.3, server CertificateVerify',
               message_range: CH..CT
             )).to be true
    end
  end

  context 'connection' do
    let(:connection) do
      connection = Connection.new(nil)
      transcript = {
        CH => ClientHello.deserialize(TESTBINARY_CLIENT_HELLO),
        SH => ServerHello.deserialize(TESTBINARY_SERVER_HELLO),
        EE => EncryptedExtensions.deserialize(TESTBINARY_ENCRYPTED_EXTENSIONS),
        CT => Certificate.deserialize(TESTBINARY_CERTIFICATE),
        CV => CertificateVerify.deserialize(TESTBINARY_CERTIFICATE_VERIFY)
      }
      connection.instance_variable_set(:@transcript, transcript)
      connection
    end

    let(:server_finished) do
      hash_len = CipherSuite.hash_len(CipherSuite::TLS_AES_128_GCM_SHA256)
      Finished.deserialize(TESTBINARY_SERVER_FINISHED, hash_len)
    end

    it 'should verify server Finished.verify_data' do
      expect(connection.do_verify_finished(
               digest: 'SHA256',
               finished_key: TESTBINARY_SERVER_FINISHED_KEY,
               message_range: CH..CV,
               signature: server_finished.verify_data
             )).to be true
    end
  end

  context 'connection' do
    let(:hash_len) do
      CipherSuite.hash_len(CipherSuite::TLS_AES_128_GCM_SHA256)
    end

    let(:connection) do
      connection = Connection.new(nil)
      transcript = {
        CH => ClientHello.deserialize(TESTBINARY_CLIENT_HELLO),
        SH => ServerHello.deserialize(TESTBINARY_SERVER_HELLO),
        EE => EncryptedExtensions.deserialize(TESTBINARY_ENCRYPTED_EXTENSIONS),
        CT => Certificate.deserialize(TESTBINARY_CERTIFICATE),
        CV => CertificateVerify.deserialize(TESTBINARY_CERTIFICATE_VERIFY),
        SF => Finished.deserialize(TESTBINARY_SERVER_FINISHED, hash_len)
      }
      connection.instance_variable_set(:@transcript, transcript)
      connection
    end

    let(:client_finished) do
      Finished.deserialize(TESTBINARY_CLIENT_FINISHED, hash_len)
    end

    it 'should sign client Finished.verify_data' do
      expect(connection.do_sign_finished(
               digest: 'SHA256',
               finished_key: TESTBINARY_CLIENT_FINISHED_KEY,
               message_range: CH..EOED
             )).to eq client_finished.verify_data
    end
  end
end
