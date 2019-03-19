# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Client do
  context 'client' do
    let(:record_ch) do
      mock_socket = SimpleStream.new
      connection = Client.new(mock_socket)
      connection.send_client_hello
      Record.deserialize(mock_socket.read, Cryptograph::Passer.new)
    end

    it 'should send default ClientHello' do
      expect(record_ch.type).to eq ContentType::HANDSHAKE

      message = record_ch.messages.first
      expect(message.msg_type).to eq HandshakeType::CLIENT_HELLO
      expect(message.legacy_version).to eq ProtocolVersion::TLS_1_2
      expect(message.cipher_suites).to eq DEFALT_CIPHER_SUITES
      expect(message.legacy_compression_methods).to eq "\x00"
    end
  end

  context 'client' do
    let(:message) do
      msg_len = TESTBINARY_SERVER_HELLO.length
      mock_socket = SimpleStream.new
      mock_socket.write(ContentType::HANDSHAKE \
                        + ProtocolVersion::TLS_1_2 \
                        + i2uint16(msg_len) \
                        + TESTBINARY_SERVER_HELLO)
      connection = Client.new(mock_socket)
      connection.recv_server_hello
    end

    it 'should receive ServerHello' do
      expect(message.msg_type).to eq HandshakeType::SERVER_HELLO
      expect(message.legacy_version).to eq ProtocolVersion::TLS_1_2
      expect(message.cipher_suite).to eq CipherSuite::TLS_AES_128_GCM_SHA256
      expect(message.legacy_compression_method).to eq "\x00"
    end
  end

  context 'client' do
    let(:client) do
      mock_socket = SimpleStream.new
      mock_socket.write(TESTBINARY_SERVER_PARAMETERS_RECORD)
      client = Client.new(mock_socket)
      client.instance_variable_set(:@cipher_suite,
                                   CipherSuite::TLS_AES_128_GCM_SHA256)
      cipher = Cryptograph::Aead.new(
        cipher_suite: CipherSuite::TLS_AES_128_GCM_SHA256,
        key: TESTBINARY_SERVER_PARAMETERS_WRITE_KEY,
        nonce: TESTBINARY_SERVER_PARAMETERS_WRITE_IV,
        type: ContentType::HANDSHAKE
      )
      client.instance_variable_set(:@read_cryptographer, cipher)
      client
    end

    it 'should receive EncryptedExtensions' do
      message = client.recv_encrypted_extensions
      expect(message.msg_type).to eq HandshakeType::ENCRYPTED_EXTENSIONS
    end

    it 'should receive Certificate' do
      client.recv_encrypted_extensions # to skip
      message = client.recv_certificate
      expect(message.msg_type).to eq HandshakeType::CERTIFICATE
    end

    it 'should receive CertificateVerify' do
      client.recv_encrypted_extensions # to skip
      client.recv_certificate          # to skip
      message = client.recv_certificate_verify
      expect(message.msg_type).to eq HandshakeType::CERTIFICATE_VERIFY
    end

    it 'should receive CertificateVerify' do
      client.recv_encrypted_extensions # to skip
      client.recv_certificate          # to skip
      client.recv_certificate_verify   # to skip
      message = client.recv_finished
      expect(message.msg_type).to eq HandshakeType::FINISHED
    end
  end

  context 'client' do
    let(:hash_len) do
      CipherSuite.hash_len(CipherSuite::TLS_AES_128_GCM_SHA256)
    end

    let(:client) do
      client = Client.new(nil)

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
      client.instance_variable_set(:@transcript_messages, tm)

      ks = KeySchedule.new(shared_secret: TESTBINARY_SHARED_SECRET,
                           cipher_suite: CipherSuite::TLS_AES_128_GCM_SHA256)
      client.instance_variable_set(:@key_schedule, ks)

      client
    end

    let(:client_finished) do
      Finished.deserialize(TESTBINARY_CLIENT_FINISHED, hash_len)
    end

    it 'should verify server Finished' do
      expect(client.verify_finished(SignatureScheme::RSA_PSS_RSAE_SHA256))
        .to be true
    end

    it 'should sign client Finished' do
      expect(client.sign_finished(SignatureScheme::RSA_PSS_RSAE_SHA256))
        .to eq client_finished.verify_data
    end
  end
end
