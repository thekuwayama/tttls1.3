# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'spec_helper'
using Refinements

RSpec.describe Server do
  context 'server' do
    let(:message) do
      msg_len = TESTBINARY_CLIENT_HELLO.length
      mock_socket = SimpleStream.new
      mock_socket.write(ContentType::HANDSHAKE \
                        + ProtocolVersion::TLS_1_2 \
                        + msg_len.to_uint16 \
                        + TESTBINARY_CLIENT_HELLO)
      server = Server.new(mock_socket)
      server.send(:recv_client_hello, true).first
    end

    it 'should receive ClientHello' do
      expect(message.msg_type).to eq HandshakeType::CLIENT_HELLO
      expect(message.legacy_version).to eq ProtocolVersion::TLS_1_2
      expect(message.legacy_compression_methods).to eq ["\x00"]
    end
  end

  context 'server' do
    let(:crt) do
      OpenSSL::X509::Certificate.new(
        File.read(__dir__ + '/fixtures/rsa_rsa.crt')
      )
    end

    let(:ch) do
      ch = ClientHello.deserialize(TESTBINARY_CLIENT_HELLO)

      # X25519 is unsupported so @named_group uses SECP256R1.
      key_share = KeyShare.new(
        msg_type: HandshakeType::CLIENT_HELLO,
        key_share_entry: [
          KeyShareEntry.new(
            group: NamedGroup::SECP256R1,
            key_exchange: "\x04" + OpenSSL::Random.random_bytes(64)
          )
        ]
      )
      ch.extensions[ExtensionType::KEY_SHARE] = key_share
      ch
    end

    let(:server) do
      Server.new(nil)
    end

    it 'should select parameters' do
      expect(server.send(:select_cipher_suite, ch))
        .to eq CipherSuite::TLS_AES_128_GCM_SHA256
      expect(server.send(:select_named_group, ch)).to eq NamedGroup::SECP256R1
      expect(server.send(:select_signature_scheme, ch, crt))
        .to eq SignatureScheme::RSA_PSS_RSAE_SHA256
    end
  end

  context 'server' do
    let(:ch) do
      ClientHello.deserialize(TESTBINARY_CLIENT_HELLO)
    end

    let(:server) do
      Server.new(nil)
    end

    it 'should generate EncryptedExtensions' do
      ee = server.send(:gen_encrypted_extensions, ch)
      expect(ee).to be_a_kind_of(EncryptedExtensions)
      expect(ee.extensions).to include(ExtensionType::SERVER_NAME)
      expect(ee.extensions[ExtensionType::SERVER_NAME].server_name).to eq ''
      expect(ee.extensions).to include(ExtensionType::SUPPORTED_GROUPS)
      expect(ee.extensions[ExtensionType::SUPPORTED_GROUPS].named_group_list)
        .to eq [NamedGroup::SECP256R1,
                NamedGroup::SECP384R1,
                NamedGroup::SECP521R1]
    end
  end

  context 'server' do
    let(:crt) do
      OpenSSL::X509::Certificate.new(
        File.read(__dir__ + '/fixtures/rsa_rsa.crt')
      )
    end

    let(:ch) do
      ClientHello.deserialize(TESTBINARY_CLIENT_HELLO)
    end

    let(:server) do
      Server.new(nil)
    end

    it 'should generate Certificate' do
      ct = server.send(:gen_certificate, crt, ch)
      expect(ct).to be_a_kind_of(Certificate)

      certificate_entry = ct.certificate_list.first
      expect(certificate_entry.cert_data.subject.to_s).to eq '/CN=localhost'
    end
  end

  context 'server' do
    let(:key) do
      rsa = OpenSSL::PKey::RSA.new
      rsa.set_key(OpenSSL::BN.new(TESTBINARY_PKEY_MODULUS, 2),
                  OpenSSL::BN.new(TESTBINARY_PKEY_PUBLIC_EXPONENT, 2),
                  OpenSSL::BN.new(TESTBINARY_PKEY_PRIVATE_EXPONENT, 2))
      rsa.set_factors(OpenSSL::BN.new(TESTBINARY_PKEY_PRIME1, 2),
                      OpenSSL::BN.new(TESTBINARY_PKEY_PRIME2, 2))
      rsa
    end

    let(:ct) do
      Certificate.deserialize(TESTBINARY_CERTIFICATE)
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
        CT => [ct, TESTBINARY_CERTIFICATE]
      )
    end

    let(:cipher_suite) do
      CipherSuite::TLS_AES_128_GCM_SHA256
    end

    let(:signature_scheme) do
      SignatureScheme::RSA_PSS_RSAE_SHA256
    end

    let(:server) do
      Server.new(nil)
    end

    it 'should generate CertificateVerify' do
      digest = CipherSuite.digest(cipher_suite)
      hash = transcript.hash(digest, CT)
      cv = server.send(:gen_certificate_verify, key, signature_scheme, hash)
      expect(cv).to be_a_kind_of(CertificateVerify)

      # used RSASSA-PSS signature_scheme, salt is a random sequence.
      # CertificateVerify.signature is random.
      public_key = ct.certificate_list.first.cert_data.public_key
      signature_scheme = cv.signature_scheme
      signature = cv.signature
      digest = CipherSuite.digest(cipher_suite)
      expect(server.send(:do_verified_certificate_verify?,
                         public_key: public_key,
                         signature_scheme: signature_scheme,
                         signature: signature,
                         context: 'TLS 1.3, server CertificateVerify',
                         hash: transcript.hash(digest, CT)))
        .to be true
    end
  end

  context 'server' do
    let(:cipher_suite) do
      CipherSuite::TLS_AES_128_GCM_SHA256
    end

    let(:transcript) do
      ch = ClientHello.deserialize(TESTBINARY_CLIENT_HELLO)
      sh = ServerHello.deserialize(TESTBINARY_SERVER_HELLO)
      ee = EncryptedExtensions.deserialize(TESTBINARY_ENCRYPTED_EXTENSIONS)
      ct = Certificate.deserialize(TESTBINARY_CERTIFICATE)
      cv = CertificateVerify.deserialize(TESTBINARY_CERTIFICATE_VERIFY)
      transcript = Transcript.new
      transcript.merge!(
        CH => [ch, TESTBINARY_CLIENT_HELLO],
        SH => [sh, TESTBINARY_SERVER_HELLO],
        EE => [ee, TESTBINARY_ENCRYPTED_EXTENSIONS],
        CT => [ct, TESTBINARY_CERTIFICATE],
        CV => [cv, TESTBINARY_CERTIFICATE_VERIFY]
      )
      transcript
    end

    let(:key_schedule) do
      KeySchedule.new(shared_secret: TESTBINARY_SHARED_SECRET,
                      cipher_suite: cipher_suite,
                      transcript: transcript)
    end

    let(:signature) do
      server = Server.new(nil)
      digest = CipherSuite.digest(cipher_suite)
      server.send(:sign_finished,
                  digest: digest,
                  finished_key: key_schedule.server_finished_key,
                  hash: transcript.hash(digest, CV))
    end

    let(:sf) do
      Finished.deserialize(TESTBINARY_SERVER_FINISHED)
    end

    it 'should generate Finished' do
      expect(signature).to eq sf.verify_data
    end
  end
end
