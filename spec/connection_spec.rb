# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Connection do
  context 'connection' do
    let(:transcript_messages) do
      ch = ClientHello.deserialize(TESTBINARY_CLIENT_HELLO)
      sh = ServerHello.deserialize(TESTBINARY_SERVER_HELLO)
      ee = EncryptedExtensions.deserialize(TESTBINARY_ENCRYPTED_EXTENSIONS)
      ct = Certificate.deserialize(TESTBINARY_CERTIFICATE)
      cv = CertificateVerify.deserialize(TESTBINARY_CERTIFICATE_VERIFY)
      {
        CLIENT_HELLO: ch,
        SERVER_HELLO: sh,
        ENCRYPTED_EXTENSIONS: ee,
        CERTIFICATE: ct,
        CERTIFICATE_VERIFY: cv
      }
    end

    let(:connection) do
      connection = Connection.new(nil)
      connection.instance_variable_set(:@transcript_messages,
                                       transcript_messages)
      connection
    end

    it 'should verify CertificateVerify.signature' do
      expect(connection.verify_certificate_verify).to be true
    end
  end

  context 'connection' do
    let(:hash_len) do
      CipherSuite.hash_len(CipherSuite::TLS_AES_128_GCM_SHA256)
    end

    let(:transcript_messages) do
      ch = ClientHello.deserialize(TESTBINARY_CLIENT_HELLO)
      sh = ServerHello.deserialize(TESTBINARY_SERVER_HELLO)
      ee = EncryptedExtensions.deserialize(TESTBINARY_ENCRYPTED_EXTENSIONS)
      ct = Certificate.deserialize(TESTBINARY_CERTIFICATE)
      cv = CertificateVerify.deserialize(TESTBINARY_CERTIFICATE_VERIFY)
      sf = Finished.deserialize(TESTBINARY_SERVER_FINISHED, hash_len)
      {
        CLIENT_HELLO: ch,
        SERVER_HELLO: sh,
        ENCRYPTED_EXTENSIONS: ee,
        CERTIFICATE: ct,
        CERTIFICATE_VERIFY: cv,
        SERVER_FINISHED: sf
      }
    end

    let(:connection) do
      connection = Connection.new(nil)
      connection.instance_variable_set(:@transcript_messages,
                                       transcript_messages)
      connection
    end

    let(:client_finished) do
      Finished.deserialize(TESTBINARY_CLIENT_FINISHED, hash_len)
    end

    it 'should sign Client Finished.verify_data' do
      expect(connection.sign_finished(
               signature_scheme: SignatureScheme::RSA_PSS_RSAE_SHA256,
               finished_key: TESTBINARY_CLIENT_FINISHED_KEY
             )).to eq client_finished.verify_data
    end
  end
end
