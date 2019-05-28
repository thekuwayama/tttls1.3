# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'spec_helper'
using Refinements

RSpec.describe Client do
  context 'client' do
    let(:record) do
      mock_socket = SimpleStream.new
      client = Client.new(mock_socket, 'localhost')
      extensions, _priv_keys = client.send(:gen_ch_extensions)
      client.send(:send_client_hello, extensions)
      Record.deserialize(mock_socket.read, Cryptograph::Passer.new)
    end

    it 'should send default ClientHello' do
      expect(record.type).to eq ContentType::HANDSHAKE

      message = record.messages.first
      expect(message.msg_type).to eq HandshakeType::CLIENT_HELLO
      expect(message.legacy_version).to eq ProtocolVersion::TLS_1_2
      expect(message.cipher_suites)
        .to eq [CipherSuite::TLS_AES_256_GCM_SHA384,
                CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
                CipherSuite::TLS_AES_128_GCM_SHA256]
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
      client = Client.new(mock_socket, 'localhost')
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
      client = Client.new(mock_socket, 'localhost')
      client.instance_variable_set(:@cipher_suite,
                                   CipherSuite::TLS_AES_128_GCM_SHA256)
      cipher = Cryptograph::Aead.new(
        cipher_suite: CipherSuite::TLS_AES_128_GCM_SHA256,
        write_key: TESTBINARY_SERVER_PARAMETERS_WRITE_KEY,
        write_iv: TESTBINARY_SERVER_PARAMETERS_WRITE_IV,
        sequence_number: SequenceNumber.new
      )
      client.instance_variable_set(:@read_cipher, cipher)
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
    let(:cipher_suite) do
      CipherSuite::TLS_AES_128_GCM_SHA256
    end

    let(:transcript) do
      transcript = Transcript.new
      transcript.merge!(
        CH => ClientHello.deserialize(TESTBINARY_CLIENT_HELLO),
        SH => ServerHello.deserialize(TESTBINARY_SERVER_HELLO),
        EE => EncryptedExtensions.deserialize(TESTBINARY_ENCRYPTED_EXTENSIONS),
        CT => Certificate.deserialize(TESTBINARY_CERTIFICATE),
        CV => CertificateVerify.deserialize(TESTBINARY_CERTIFICATE_VERIFY),
        SF => Finished.deserialize(TESTBINARY_SERVER_FINISHED)
      )
      transcript
    end

    let(:finished_key) do
      key_schedule = KeySchedule.new(
        shared_secret: TESTBINARY_SHARED_SECRET,
        cipher_suite: cipher_suite,
        transcript: transcript
      )
      key_schedule.client_finished_key
    end

    let(:record) do
      mock_socket = SimpleStream.new
      client = Client.new(mock_socket, 'localhost')
      write_cipher = Cryptograph::Aead.new(
        cipher_suite: cipher_suite,
        write_key: TESTBINARY_CLIENT_FINISHED_WRITE_KEY,
        write_iv: TESTBINARY_CLIENT_FINISHED_WRITE_IV,
        sequence_number: SequenceNumber.new
      )
      client.instance_variable_set(:@write_cipher, write_cipher)
      digest = CipherSuite.digest(cipher_suite)
      hash = transcript.hash(digest, EOED)
      signature = client.send(:sign_finished,
                              digest: digest,
                              finished_key: finished_key,
                              hash: hash)
      client.send(:send_finished, signature)
      read_cipher = Cryptograph::Aead.new(
        cipher_suite: cipher_suite,
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
    let(:cipher_suite) do
      CipherSuite::TLS_AES_128_GCM_SHA256
    end

    let(:ct) do
      Certificate.deserialize(TESTBINARY_CERTIFICATE)
    end

    let(:cv) do
      CertificateVerify.deserialize(TESTBINARY_CERTIFICATE_VERIFY)
    end

    let(:sf) do
      Finished.deserialize(TESTBINARY_SERVER_FINISHED)
    end

    let(:transcript) do
      transcript = Transcript.new
      transcript.merge!(
        CH => ClientHello.deserialize(TESTBINARY_CLIENT_HELLO),
        SH => ServerHello.deserialize(TESTBINARY_SERVER_HELLO),
        EE => EncryptedExtensions.deserialize(TESTBINARY_ENCRYPTED_EXTENSIONS),
        CT => ct,
        CV => cv,
        SF => sf
      )
    end

    let(:key_schedule) do
      KeySchedule.new(
        shared_secret: TESTBINARY_SHARED_SECRET,
        cipher_suite: cipher_suite,
        transcript: transcript
      )
    end

    let(:client) do
      Client.new(nil, 'localhost')
    end

    let(:cf) do
      Finished.deserialize(TESTBINARY_CLIENT_FINISHED)
    end

    it 'should verify server CertificateVerify' do
      hash = transcript.hash(CipherSuite.digest(cipher_suite), CT)
      expect(client.send(:verified_certificate_verify?, ct, cv, hash))
        .to be true
    end

    it 'should verify server Finished' do
      digest = CipherSuite.digest(cipher_suite)
      hash = transcript.hash(digest, CV)
      expect(client.send(:verified_finished?,
                         finished: sf,
                         digest: digest,
                         finished_key: key_schedule.server_finished_key,
                         hash: hash)).to be true
    end

    it 'should sign client Finished' do
      digest = CipherSuite.digest(cipher_suite)
      hash = transcript.hash(digest, EOED)
      expect(client.send(:sign_finished,
                         digest: digest,
                         finished_key: key_schedule.client_finished_key,
                         hash: hash)).to eq cf.verify_data
    end
  end

  context 'client, received Certificate signed by private CA,' do
    let(:certificate) do
      server_crt = OpenSSL::X509::Certificate.new(
        File.read(__dir__ + '/fixtures/rsa_rsa.crt')
      )
      Certificate.new(certificate_list: [CertificateEntry.new(server_crt)])
    end

    let(:client) do
      Client.new(nil, 'localhost')
    end

    it 'should not certify certificate' do
      expect(client.send(:trusted_certificate?, certificate.certificate_list))
        .to be false
    end

    it 'should certify certificate, received path to private ca.crt' do
      expect(client.send(:trusted_certificate?, certificate.certificate_list,
                         __dir__ + '/fixtures/rsa_ca.crt')).to be true
    end
  end

  context 'client using PSK' do
    let(:client) do
      Client.new(nil, 'localhost')
    end

    let(:ticket_nonce) do
      nst = NewSessionTicket.deserialize(TESTBINARY_NEW_SESSION_TICKET)
      nst.ticket_nonce
    end

    it 'should generate PSK from NewSessionTicket of previous handshake' do
      expect(client.send(:gen_psk_from_nst, TESTBINARY_RES_MASTER, ticket_nonce,
                         'SHA256')).to eq TESTBINARY_0_RTT_PSK
    end
  end
end
