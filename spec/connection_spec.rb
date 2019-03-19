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
      ch = ClientHello.deserialize(TESTBINARY_CLIENT_HELLO)
      sh = ServerHello.deserialize(TESTBINARY_SERVER_HELLO)
      ee = EncryptedExtensions.deserialize(TESTBINARY_ENCRYPTED_EXTENSIONS)
      tm = {
        CLIENT_HELLO: ch,
        SERVER_HELLO: sh,
        ENCRYPTED_EXTENSIONS: ee,
        SERVER_CERTIFICATE: ct,
        SERVER_CERTIFICATE_VERIFY: cv
      }
      connection.instance_variable_set(:@transcript_messages, tm)
      connection
    end

    it 'should verify server CertificateVerify.signature' do
      expect(connection.do_verify_certificate_verify(
               certificate_pem: ct.certificate_list.first.cert_data.to_pem,
               signature_scheme: cv.signature_scheme,
               signature: cv.signature,
               context: 'TLS 1.3, server CertificateVerify',
               message_syms: Connection::CH_CT
             )).to be true
    end
  end

  context 'connection' do
    let(:connection) do
      connection = Connection.new(nil)
      ch = ClientHello.deserialize(TESTBINARY_CLIENT_HELLO)
      sh = ServerHello.deserialize(TESTBINARY_SERVER_HELLO)
      ee = EncryptedExtensions.deserialize(TESTBINARY_ENCRYPTED_EXTENSIONS)
      ct = Certificate.deserialize(TESTBINARY_CERTIFICATE)
      cv = CertificateVerify.deserialize(TESTBINARY_CERTIFICATE_VERIFY)
      tm = {
        CLIENT_HELLO: ch,
        SERVER_HELLO: sh,
        ENCRYPTED_EXTENSIONS: ee,
        SERVER_CERTIFICATE: ct,
        SERVER_CERTIFICATE_VERIFY: cv
      }
      connection.instance_variable_set(:@transcript_messages, tm)
      connection
    end

    let(:server_finished) do
      hash_len = CipherSuite.hash_len(CipherSuite::TLS_AES_128_GCM_SHA256)
      Finished.deserialize(TESTBINARY_SERVER_FINISHED, hash_len)
    end

    it 'should verify server Finished.verify_data' do
      expect(connection.do_verify_finished(
               signature_scheme: SignatureScheme::RSA_PSS_RSAE_SHA256,
               finished_key: TESTBINARY_SERVER_FINISHED_KEY,
               message_syms: Connection::CH_CV,
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
      ch = ClientHello.deserialize(TESTBINARY_CLIENT_HELLO)
      sh = ServerHello.deserialize(TESTBINARY_SERVER_HELLO)
      ee = EncryptedExtensions.deserialize(TESTBINARY_ENCRYPTED_EXTENSIONS)
      ct = Certificate.deserialize(TESTBINARY_CERTIFICATE)
      cv = CertificateVerify.deserialize(TESTBINARY_CERTIFICATE_VERIFY)
      sf = Finished.deserialize(TESTBINARY_SERVER_FINISHED, hash_len)
      tm = {
        CLIENT_HELLO: ch,
        SERVER_HELLO: sh,
        ENCRYPTED_EXTENSIONS: ee,
        SERVER_CERTIFICATE: ct,
        SERVER_CERTIFICATE_VERIFY: cv,
        SERVER_FINISHED: sf
      }
      connection.instance_variable_set(:@transcript_messages, tm)
      connection
    end

    let(:client_finished) do
      Finished.deserialize(TESTBINARY_CLIENT_FINISHED, hash_len)
    end

    it 'should sign client Finished.verify_data' do
      expect(connection.do_sign_finished(
               signature_scheme: SignatureScheme::RSA_PSS_RSAE_SHA256,
               finished_key: TESTBINARY_CLIENT_FINISHED_KEY,
               message_syms: Connection::CH_SF
             )).to eq client_finished.verify_data
    end
  end
end
