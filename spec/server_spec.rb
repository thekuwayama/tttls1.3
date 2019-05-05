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
    let(:private_key) do
      rsa = OpenSSL::PKey::RSA.new
      rsa.set_key(OpenSSL::BN.new(TESTBINARY_PKEY_MODULUS, 2),
                  OpenSSL::BN.new(TESTBINARY_PKEY_PUBLIC_EXPONENT, 2),
                  OpenSSL::BN.new(TESTBINARY_PKEY_PRIVATE_EXPONENT, 2))
      rsa.set_factors(OpenSSL::BN.new(TESTBINARY_PKEY_PRIME1, 2),
                      OpenSSL::BN.new(TESTBINARY_PKEY_PRIME2, 2))
    end

    let(:server) do
      server = Server.new(nil)
      server.instance_variable_set(:@private_key, private_key)
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
      server.instance_variable_set(:@signature_scheme,
                                   SignatureScheme::RSA_PSS_RSAE_SHA256)
      server
    end

    let(:server_finished) do
      Finished.deserialize(TESTBINARY_SERVER_FINISHED)
    end

    it 'should sign server Finished' do
      expect(server.send(:sign_finished)).to eq server_finished.verify_data
    end
  end
end
