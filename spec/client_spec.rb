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
    let(:connection) do
      mock_socket = SimpleStream.new
      mock_socket.write(TESTBINARY_SERVER_PARAMETERS_RECORD)
      connection = Client.new(mock_socket)
      connection.instance_variable_set(:@cipher_suite,
                                       CipherSuite::TLS_AES_128_GCM_SHA256)
      cipher = Cryptograph::Aead.new(
        cipher_suite: CipherSuite::TLS_AES_128_GCM_SHA256,
        key: TESTBINARY_SERVER_PARAMETERS_WRITE_KEY,
        nonce: TESTBINARY_SERVER_PARAMETERS_WRITE_IV,
        type: ContentType::HANDSHAKE
      )
      connection.instance_variable_set(:@read_cryptographer, cipher)
      connection
    end

    it 'should receive EncryptedExtensions' do
      message = connection.recv_encrypted_extensions
      expect(message.msg_type).to eq HandshakeType::ENCRYPTED_EXTENSIONS
    end

    it 'should receive Certificate' do
      connection.recv_encrypted_extensions # to skip
      message = connection.recv_certificate
      expect(message.msg_type).to eq HandshakeType::CERTIFICATE
    end

    it 'should receive CertificateVerify' do
      connection.recv_encrypted_extensions # to skip
      connection.recv_certificate # to skip
      message = connection.recv_certificate_verify
      expect(message.msg_type).to eq HandshakeType::CERTIFICATE_VERIFY
    end
  end
end
