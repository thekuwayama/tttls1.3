# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Client do
  context 'client' do
    let(:record) do
      mock_socket = SimpleStream.new
      client = Client.new(mock_socket)
      client.send_client_hello
      Record.deserialize(mock_socket.read, Cryptograph::Passer.new)
    end

    it 'should send default ClientHello' do
      expect(record.type).to eq ContentType::HANDSHAKE

      message = record.messages.first
      expect(message.msg_type).to eq HandshakeType::CLIENT_HELLO
      expect(message.legacy_version).to eq ProtocolVersion::TLS_1_2
      expect(message.cipher_suites).to eq [CipherSuite::TLS_AES_128_GCM_SHA256]
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
      client = Client.new(mock_socket)
      client.recv_server_hello
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
      read_seq_number = SequenceNumber.new
      cipher = Cryptograph::Aead.new(
        cipher_suite: CipherSuite::TLS_AES_128_GCM_SHA256,
        write_key: TESTBINARY_SERVER_PARAMETERS_WRITE_KEY,
        write_iv: TESTBINARY_SERVER_PARAMETERS_WRITE_IV,
        sequence_number: read_seq_number,
        opaque_type: ContentType::HANDSHAKE
      )
      client.instance_variable_set(:@read_cryptographer, cipher)
      client.instance_variable_set(:@read_seq_number, read_seq_number)
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

    it 'should receive Finished' do
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

    let(:record) do
      mock_socket = SimpleStream.new
      client = Client.new(mock_socket)
      transcript = {
        CH => ClientHello.deserialize(TESTBINARY_CLIENT_HELLO),
        SH => ServerHello.deserialize(TESTBINARY_SERVER_HELLO),
        EE => EncryptedExtensions.deserialize(TESTBINARY_ENCRYPTED_EXTENSIONS),
        CT => Certificate.deserialize(TESTBINARY_CERTIFICATE),
        CV => CertificateVerify.deserialize(TESTBINARY_CERTIFICATE_VERIFY),
        SF => Finished.deserialize(TESTBINARY_SERVER_FINISHED, hash_len)
      }
      client.instance_variable_set(:@transcript, transcript)
      ks = KeySchedule.new(shared_secret: TESTBINARY_SHARED_SECRET,
                           cipher_suite: CipherSuite::TLS_AES_128_GCM_SHA256)
      client.instance_variable_set(:@key_schedule, ks)
      client.instance_variable_set(:@cipher_suite,
                                   CipherSuite::TLS_AES_128_GCM_SHA256)
      write_seq_number = SequenceNumber.new
      write_cipher = Cryptograph::Aead.new(
        cipher_suite: CipherSuite::TLS_AES_128_GCM_SHA256,
        write_key: TESTBINARY_CLIENT_FINISHED_WRITE_KEY,
        write_iv: TESTBINARY_CLIENT_FINISHED_WRITE_IV,
        sequence_number: write_seq_number,
        opaque_type: ContentType::HANDSHAKE
      )
      client.instance_variable_set(:@write_cryptographer, write_cipher)
      client.instance_variable_set(:@write_seq_number, write_seq_number)
      client.send_finished
      read_cipher = Cryptograph::Aead.new(
        cipher_suite: CipherSuite::TLS_AES_128_GCM_SHA256,
        write_key: TESTBINARY_CLIENT_FINISHED_WRITE_KEY,
        write_iv: TESTBINARY_CLIENT_FINISHED_WRITE_IV,
        sequence_number: SequenceNumber.new,
        opaque_type: ContentType::HANDSHAKE
      )
      Record.deserialize(mock_socket.read, read_cipher)
    end

    it 'should send Finished' do
      expect(record.type).to eq ContentType::APPLICATION_DATA

      message = Message.deserialize_handshake(record.messages.first.fragment,
                                              hash_len)
      expect(message.msg_type).to eq HandshakeType::FINISHED
      expect(message.serialize).to eq TESTBINARY_CLIENT_FINISHED
    end
  end

  context 'client' do
    let(:hash_len) do
      CipherSuite.hash_len(CipherSuite::TLS_AES_128_GCM_SHA256)
    end

    let(:client) do
      client = Client.new(nil)
      transcript = {
        CH => ClientHello.deserialize(TESTBINARY_CLIENT_HELLO),
        SH => ServerHello.deserialize(TESTBINARY_SERVER_HELLO),
        EE => EncryptedExtensions.deserialize(TESTBINARY_ENCRYPTED_EXTENSIONS),
        CT => Certificate.deserialize(TESTBINARY_CERTIFICATE),
        CV => CertificateVerify.deserialize(TESTBINARY_CERTIFICATE_VERIFY),
        SF => Finished.deserialize(TESTBINARY_SERVER_FINISHED, hash_len)
      }
      client.instance_variable_set(:@transcript, transcript)
      ks = KeySchedule.new(shared_secret: TESTBINARY_SHARED_SECRET,
                           cipher_suite: CipherSuite::TLS_AES_128_GCM_SHA256)
      client.instance_variable_set(:@key_schedule, ks)
      client.instance_variable_set(:@cipher_suite,
                                   CipherSuite::TLS_AES_128_GCM_SHA256)
      client
    end

    let(:client_finished) do
      Finished.deserialize(TESTBINARY_CLIENT_FINISHED, hash_len)
    end

    it 'should verify server CertificateVerify' do
      expect(client.verify_certificate_verify).to be true
    end

    it 'should verify server Finished' do
      expect(client.verify_finished).to be true
    end

    it 'should sign client Finished' do
      expect(client.sign_finished).to eq client_finished.verify_data
    end
  end
end
