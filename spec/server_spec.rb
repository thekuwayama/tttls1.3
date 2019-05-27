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
      server.send(:recv_client_hello)
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
      server = Server.new(nil)
      server.instance_variable_set(:@crt, crt)
      server
    end

    it 'should select parameters' do
      expect(server.send(:select_cipher_suite, ch))
        .to eq CipherSuite::TLS_AES_128_GCM_SHA256
      expect(server.send(:select_named_group, ch)).to eq NamedGroup::SECP256R1
      expect(server.send(:select_signature_scheme, ch))
        .to eq SignatureScheme::RSA_PSS_RSAE_SHA256
    end
  end

  context 'server' do
    let(:server) do
      server = Server.new(nil)
      transcript = Transcript.new
      transcript[CH] = ClientHello.deserialize(TESTBINARY_CLIENT_HELLO)
      server.instance_variable_set(:@transcript, transcript)
      server
    end

    it 'should generate EncryptedExtensions' do
      ee = server.send(:gen_encrypted_extensions)
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
    let(:server) do
      server = Server.new(nil)
      crt = OpenSSL::X509::Certificate.new(
        File.read(__dir__ + '/fixtures/rsa_rsa.crt')
      )
      server.instance_variable_set(:@crt, crt)
      server
    end

    it 'should generate Certificate' do
      ct = server.send(:gen_certificate)
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
      transcript = Transcript.new
      transcript.merge!(
        CH => ClientHello.deserialize(TESTBINARY_CLIENT_HELLO),
        SH => ServerHello.deserialize(TESTBINARY_SERVER_HELLO),
        EE => EncryptedExtensions.deserialize(TESTBINARY_ENCRYPTED_EXTENSIONS),
        CT => ct
      )
    end

    let(:cipher_suite) do
      CipherSuite::TLS_AES_128_GCM_SHA256
    end

    let(:signature_scheme) do
      SignatureScheme::RSA_PSS_RSAE_SHA256
    end

    let(:server) do
      server = Server.new(nil)
      server.instance_variable_set(:@key, key)
      server.instance_variable_set(:@transcript, transcript)
      server.instance_variable_set(:@cipher_suite, cipher_suite)
      server.instance_variable_set(:@signature_scheme, signature_scheme)
      server
    end

    it 'should generate CertificateVerify' do
      cv = server.send(:gen_certificate_verify)
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
    let(:server) do
      server = Server.new(nil)
      transcript = Transcript.new
      transcript.merge!(
        CH => ClientHello.deserialize(TESTBINARY_CLIENT_HELLO),
        SH => ServerHello.deserialize(TESTBINARY_SERVER_HELLO),
        EE => EncryptedExtensions.deserialize(TESTBINARY_ENCRYPTED_EXTENSIONS),
        CT => Certificate.deserialize(TESTBINARY_CERTIFICATE),
        CV => CertificateVerify.deserialize(TESTBINARY_CERTIFICATE_VERIFY)
      )
      server.instance_variable_set(:@transcript, transcript)
      ks = KeySchedule.new(shared_secret: TESTBINARY_SHARED_SECRET,
                           cipher_suite: CipherSuite::TLS_AES_128_GCM_SHA256,
                           transcript: transcript)
      server.instance_variable_set(:@key_schedule, ks)
      server.instance_variable_set(:@cipher_suite,
                                   CipherSuite::TLS_AES_128_GCM_SHA256)
      server
    end

    let(:verify_data) do
      Finished.deserialize(TESTBINARY_SERVER_FINISHED).verify_data
    end

    it 'should generate Finished' do
      sf = server.send(:gen_finished)
      expect(sf).to be_a_kind_of(Finished)
      expect(sf.verify_data).to eq verify_data
    end
  end
end
