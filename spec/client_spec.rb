# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'
using Refinements

RSpec.describe Client do
  context 'client' do
    let(:record) do
      mock_socket = SimpleStream.new
      client = Client.new(mock_socket)
      client.send(:send_client_hello)
      Record.deserialize(mock_socket.read, Cryptograph::Passer.new)
    end

    it 'should send default ClientHello' do
      expect(record.type).to eq ContentType::HANDSHAKE

      message = record.messages.first
      expect(message.msg_type).to eq HandshakeType::CLIENT_HELLO
      expect(message.legacy_version).to eq ProtocolVersion::TLS_1_2
      expect(message.cipher_suites).to eq DEFAULT_CIPHER_SUITES
      expect(message.legacy_compression_methods).to eq ["\x00"]
    end
  end

  context 'client' do
    let(:message) do
      msg_len = TESTBINARY_SERVER_HELLO.length
      mock_socket = SimpleStream.new
      mock_socket.write(ContentType::HANDSHAKE \
                        + ProtocolVersion::TLS_1_2 \
                        + msg_len.to_uint16 \
                        + TESTBINARY_SERVER_HELLO)
      client = Client.new(mock_socket)
      client.send(:recv_server_hello)
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
      read_seq_num = SequenceNumber.new
      cipher = Cryptograph::Aead.new(
        cipher_suite: CipherSuite::TLS_AES_128_GCM_SHA256,
        write_key: TESTBINARY_SERVER_PARAMETERS_WRITE_KEY,
        write_iv: TESTBINARY_SERVER_PARAMETERS_WRITE_IV,
        sequence_number: read_seq_num
      )
      client.instance_variable_set(:@read_cipher, cipher)
      client.instance_variable_set(:@read_seq_num, read_seq_num)
      client
    end

    it 'should receive EncryptedExtensions' do
      message = client.send(:recv_encrypted_extensions)
      expect(message.msg_type).to eq HandshakeType::ENCRYPTED_EXTENSIONS
    end

    it 'should receive Certificate' do
      client.send(:recv_encrypted_extensions) # to skip
      message = client.send(:recv_certificate)
      expect(message.msg_type).to eq HandshakeType::CERTIFICATE
    end

    it 'should receive CertificateVerify' do
      client.send(:recv_encrypted_extensions) # to skip
      client.send(:recv_certificate)          # to skip
      message = client.send(:recv_certificate_verify)
      expect(message.msg_type).to eq HandshakeType::CERTIFICATE_VERIFY
    end

    it 'should receive Finished' do
      client.send(:recv_encrypted_extensions) # to skip
      client.send(:recv_certificate)          # to skip
      client.send(:recv_certificate_verify)   # to skip
      message = client.send(:recv_finished)
      expect(message.msg_type).to eq HandshakeType::FINISHED
    end
  end

  context 'client' do
    let(:record) do
      mock_socket = SimpleStream.new
      client = Client.new(mock_socket)
      transcript = {
        CH => ClientHello.deserialize(TESTBINARY_CLIENT_HELLO),
        SH => ServerHello.deserialize(TESTBINARY_SERVER_HELLO),
        EE => EncryptedExtensions.deserialize(TESTBINARY_ENCRYPTED_EXTENSIONS),
        CT => Certificate.deserialize(TESTBINARY_CERTIFICATE),
        CV => CertificateVerify.deserialize(TESTBINARY_CERTIFICATE_VERIFY),
        SF => Finished.deserialize(TESTBINARY_SERVER_FINISHED)
      }
      client.instance_variable_set(:@transcript, transcript)
      ks = KeySchedule.new(shared_secret: TESTBINARY_SHARED_SECRET,
                           cipher_suite: CipherSuite::TLS_AES_128_GCM_SHA256)
      client.instance_variable_set(:@key_schedule, ks)
      client.instance_variable_set(:@cipher_suite,
                                   CipherSuite::TLS_AES_128_GCM_SHA256)
      write_seq_num = SequenceNumber.new
      write_cipher = Cryptograph::Aead.new(
        cipher_suite: CipherSuite::TLS_AES_128_GCM_SHA256,
        write_key: TESTBINARY_CLIENT_FINISHED_WRITE_KEY,
        write_iv: TESTBINARY_CLIENT_FINISHED_WRITE_IV,
        sequence_number: write_seq_num
      )
      client.instance_variable_set(:@write_cipher, write_cipher)
      client.instance_variable_set(:@write_seq_num, write_seq_num)
      client.send(:send_finished)
      read_cipher = Cryptograph::Aead.new(
        cipher_suite: CipherSuite::TLS_AES_128_GCM_SHA256,
        write_key: TESTBINARY_CLIENT_FINISHED_WRITE_KEY,
        write_iv: TESTBINARY_CLIENT_FINISHED_WRITE_IV,
        sequence_number: SequenceNumber.new
      )
      Record.deserialize(mock_socket.read, read_cipher)
    end

    it 'should send Finished' do
      expect(record.type).to eq ContentType::APPLICATION_DATA

      message = record.messages.first
      expect(message.msg_type).to eq HandshakeType::FINISHED
      expect(message.serialize).to eq TESTBINARY_CLIENT_FINISHED
    end
  end

  context 'client' do
    let(:client) do
      client = Client.new(nil)
      transcript = {
        CH => ClientHello.deserialize(TESTBINARY_CLIENT_HELLO),
        SH => ServerHello.deserialize(TESTBINARY_SERVER_HELLO),
        EE => EncryptedExtensions.deserialize(TESTBINARY_ENCRYPTED_EXTENSIONS),
        CT => Certificate.deserialize(TESTBINARY_CERTIFICATE),
        CV => CertificateVerify.deserialize(TESTBINARY_CERTIFICATE_VERIFY),
        SF => Finished.deserialize(TESTBINARY_SERVER_FINISHED)
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
      Finished.deserialize(TESTBINARY_CLIENT_FINISHED)
    end

    it 'should verify server CertificateVerify' do
      expect(client.send(:verify_certificate_verify)).to be true
    end

    it 'should verify server Finished' do
      expect(client.send(:verify_finished)).to be true
    end

    it 'should sign client Finished' do
      expect(client.send(:sign_finished)).to eq client_finished.verify_data
    end
  end

  context 'client' do
    let(:client) do
      client = Client.new(nil)
      transcript = {
        CH => ClientHello.deserialize(TESTBINARY_CLIENT_HELLO),
        SH => ServerHello.deserialize(TESTBINARY_SERVER_HELLO)
      }
      client.instance_variable_set(:@transcript, transcript)
      client
    end

    it 'should check that ServerHello.legacy_session_id_echo matches ' \
       'ClientHello.legacy_session_id' do
      expect(client.send(:echoed_legacy_session_id?)).to be true
    end

    it 'should check that ServerHello.cipher_suite is included in' \
       'ClientHello.cipher_suites' do
      expect(client.send(:offerd_cipher_suite?)).to be true
    end

    it 'should check that ServerHello.compression_method is valid value' do
      expect(client.send(:valid_compression_method?)).to be true
    end

    it 'should check that negotiated protocol_version is TLS 1.3' do
      expect(client.send(:negotiated_tls_1_3?)).to be true
    end
  end

  context 'client, received ServerHello with random[-8..] == ' \
          'downgrade protection value(TLS 1.2),' do
    let(:client) do
      mock_socket = SimpleStream.new
      client = Client.new(mock_socket)
      sh = ServerHello.deserialize(TESTBINARY_SERVER_HELLO)
      random = OpenSSL::Random.random_bytes(24) + \
               Client::DOWNGRADE_PROTECTION_TLS_1_2
      sh.instance_variable_set(:@random, random)
      transcript = {
        CH => ClientHello.deserialize(TESTBINARY_CLIENT_HELLO),
        SH => sh
      }
      client.instance_variable_set(:@transcript, transcript)
      client
    end

    it 'should check downgrade protection value' do
      expect { client.send(:negotiated_tls_1_3?) }.to raise_error(TLSError)
    end
  end

  context 'client, received ServerHello with random[-8..] == ' \
          'downgrade protection value(prior to TLS 1.2),' do
    let(:client) do
      mock_socket = SimpleStream.new
      client = Client.new(mock_socket)
      sh = ServerHello.deserialize(TESTBINARY_SERVER_HELLO)
      random = OpenSSL::Random.random_bytes(24) + \
               Client::DOWNGRADE_PROTECTION_TLS_1_1
      sh.instance_variable_set(:@random, random)
      transcript = {
        CH => ClientHello.deserialize(TESTBINARY_CLIENT_HELLO),
        SH => sh
      }
      client.instance_variable_set(:@transcript, transcript)
      client
    end

    it 'should check downgrade protection value' do
      expect { client.send(:negotiated_tls_1_3?) }.to raise_error(TLSError)
    end
  end

  context 'client, received ServerHello with supported_versions not ' \
          'including "\x03\x04",' do
    let(:client) do
      mock_socket = SimpleStream.new
      client = Client.new(mock_socket)
      sh = ServerHello.deserialize(TESTBINARY_SERVER_HELLO)
      extensions = sh.instance_variable_get(:@extensions)
      extensions[ExtensionType::SUPPORTED_VERSIONS] = nil
      sh.instance_variable_set(:@extensions, extensions)
      transcript = {
        CH => ClientHello.deserialize(TESTBINARY_CLIENT_HELLO),
        SH => sh
      }
      client.instance_variable_set(:@transcript, transcript)
      client
    end

    it 'should check negotiated protocol_version' do
      expect(client.send(:negotiated_tls_1_3?)).to be false
    end
  end
end
