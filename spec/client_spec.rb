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
      Record.deserialize(mock_socket.read, Cryptograph::Passer.new).first
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
      client.send(:recv_server_hello).first
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
      Client.new(mock_socket, 'localhost')
    end

    let(:cipher) do
      Cryptograph::Aead.new(
        cipher_suite: CipherSuite::TLS_AES_128_GCM_SHA256,
        write_key: TESTBINARY_SERVER_PARAMETERS_WRITE_KEY,
        write_iv: TESTBINARY_SERVER_PARAMETERS_WRITE_IV,
        sequence_number: SequenceNumber.new
      )
    end

    it 'should receive EncryptedExtensions' do
      message, = client.send(:recv_encrypted_extensions, cipher)
      expect(message.msg_type).to eq HandshakeType::ENCRYPTED_EXTENSIONS
    end

    it 'should receive Certificate' do
      client.send(:recv_encrypted_extensions, cipher) # to skip
      message, = client.send(:recv_certificate, cipher)
      expect(message.msg_type).to eq HandshakeType::CERTIFICATE
    end

    it 'should receive CertificateVerify' do
      client.send(:recv_encrypted_extensions, cipher) # to skip
      client.send(:recv_certificate, cipher)          # to skip
      message, = client.send(:recv_certificate_verify, cipher)
      expect(message.msg_type).to eq HandshakeType::CERTIFICATE_VERIFY
    end

    it 'should receive Finished' do
      client.send(:recv_encrypted_extensions, cipher) # to skip
      client.send(:recv_certificate, cipher)          # to skip
      client.send(:recv_certificate_verify, cipher)   # to skip
      message, = client.send(:recv_finished, cipher)
      expect(message.msg_type).to eq HandshakeType::FINISHED
    end
  end

  context 'client' do
    let(:cipher_suite) do
      CipherSuite::TLS_AES_128_GCM_SHA256
    end

    let(:transcript) do
      ch = ClientHello.deserialize(TESTBINARY_CLIENT_HELLO)
      sh = ServerHello.deserialize(TESTBINARY_SERVER_HELLO)
      ee = EncryptedExtensions.deserialize(TESTBINARY_ENCRYPTED_EXTENSIONS)
      ct = Certificate.deserialize(TESTBINARY_CERTIFICATE)
      cv = CertificateVerify.deserialize(TESTBINARY_CERTIFICATE_VERIFY)
      sf = Finished.deserialize(TESTBINARY_SERVER_FINISHED)
      transcript = Transcript.new
      transcript.merge!(
        CH => [ch, TESTBINARY_CLIENT_HELLO],
        SH => [sh, TESTBINARY_SERVER_HELLO],
        EE => [ee, TESTBINARY_ENCRYPTED_EXTENSIONS],
        CT => [ct, TESTBINARY_CERTIFICATE],
        CV => [cv, TESTBINARY_CERTIFICATE_VERIFY],
        SF => [sf, TESTBINARY_SERVER_FINISHED]
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
      digest = CipherSuite.digest(cipher_suite)
      hash = transcript.hash(digest, EOED)
      signature = client.send(:sign_finished,
                              digest: digest,
                              finished_key: finished_key,
                              hash: hash)
      hs_wcipher = Cryptograph::Aead.new(
        cipher_suite: cipher_suite,
        write_key: TESTBINARY_CLIENT_FINISHED_WRITE_KEY,
        write_iv: TESTBINARY_CLIENT_FINISHED_WRITE_IV,
        sequence_number: SequenceNumber.new
      )
      client.send(:send_finished, signature, hs_wcipher)
      hs_rcipher = Cryptograph::Aead.new(
        cipher_suite: cipher_suite,
        write_key: TESTBINARY_CLIENT_FINISHED_WRITE_KEY,
        write_iv: TESTBINARY_CLIENT_FINISHED_WRITE_IV,
        sequence_number: SequenceNumber.new
      )
      Record.deserialize(mock_socket.read, hs_rcipher).first
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
        SF => [sf, TESTBINARY_SERVER_FINISHED]
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

  context 'EncodedClientHelloInner length' do
    let(:server_name) do
      'localhost'
    end

    let(:client) do
      Client.new(nil, server_name)
    end

    let(:maximum_name_length) do
      0
    end

    let(:encoded) do
      extensions, = client.send(:gen_ch_extensions)
      inner_ech = Message::Extension::ECHClientHello.new_inner
      Message::ClientHello.new(
        legacy_session_id: '',
        cipher_suites: CipherSuites.new(DEFAULT_CH_CIPHER_SUITES),
        extensions: extensions.merge(
          Message::ExtensionType::ENCRYPTED_CLIENT_HELLO => inner_ech
        )
      )
    end

    let(:padding_encoded_ch_inner) do
      client.send(
        :padding_encoded_ch_inner,
        encoded.serialize[4..],
        server_name.length,
        maximum_name_length
      )
    end

    it 'should be equal placeholder_encoded_ch_inner_len' do
      expect(client.send(:placeholder_encoded_ch_inner_len))
        .to eq padding_encoded_ch_inner.length
    end
  end
end
