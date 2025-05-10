# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'spec_helper'

FIXTURES_DIR = __dir__ + '/../spec/fixtures'
PORT = 14433

RSpec.describe Client do
  # normal [Boolean] Is this nominal scenarios?
  # opt [String] openssl s_server options
  # crt [String] server crt file path
  # key [String] server key file path
  # settings [Hash] TTTLS13::Server settings
  testcases = [
    [
      true,
      '-ciphersuites TLS_AES_256_GCM_SHA384',
      'rsa_rsa.crt',
      'rsa_rsa.key',
      { cipher_suites: [CipherSuite::TLS_AES_256_GCM_SHA384] }
    ],
    [
      true,
      '-ciphersuites TLS_CHACHA20_POLY1305_SHA256',
      'rsa_rsa.crt',
      'rsa_rsa.key',
      { cipher_suites: [CipherSuite::TLS_CHACHA20_POLY1305_SHA256] }
    ],
    [
      true,
      '-ciphersuites TLS_AES_128_GCM_SHA256',
      'rsa_rsa.crt',
      'rsa_rsa.key',
      { cipher_suites: [CipherSuite::TLS_AES_128_GCM_SHA256] }
    ],
    [
      true,
      '-ciphersuites TLS_AES_128_CCM_SHA256',
      'rsa_rsa.crt',
      'rsa_rsa.key',
      { cipher_suites: [CipherSuite::TLS_AES_128_CCM_SHA256] }
    ],
    [
      true,
      "-ciphersuites TLS_AES_128_CCM_8_SHA256 -cipher 'DEFAULT:@SECLEVEL=0'",
      'rsa_rsa.crt',
      'rsa_rsa.key',
      { cipher_suites: [CipherSuite::TLS_AES_128_CCM_8_SHA256] }
    ],
    [
      false,
      '-ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
      'rsa_rsa.crt',
      'rsa_rsa.key',
      { cipher_suites: [CipherSuite::TLS_AES_128_GCM_SHA256] }
    ],
    [
      true,
      '-groups X25519',
      'rsa_rsa.crt',
      'rsa_rsa.key',
      { supported_groups: [NamedGroup::X25519] }
    ],
    [
      true,
      '-groups X448',
      'rsa_rsa.crt',
      'rsa_rsa.key',
      { supported_groups: [NamedGroup::X448] }
    ],
    [
      true,
      '-groups P-256',
      'rsa_rsa.crt',
      'rsa_rsa.key',
      { supported_groups: [NamedGroup::SECP256R1] }
    ],
    [
      true,
      '-groups P-384',
      'rsa_rsa.crt',
      'rsa_rsa.key',
      { supported_groups: [NamedGroup::SECP384R1] }
    ],
    [
      true,
      '-groups P-521',
      'rsa_rsa.crt',
      'rsa_rsa.key',
      { supported_groups: [NamedGroup::SECP521R1] }
    ],
    [
      false,
      '-groups P-256:P-384:P-521:X448',
      'rsa_rsa.crt',
      'rsa_rsa.key',
      { supported_groups: [NamedGroup::X25519] }
    ],
    [
      true,
      '-sigalgs RSA-PSS+SHA256',
      'rsa_rsa.crt',
      'rsa_rsa.key',
      { signature_algorithms_cert: [SignatureScheme::RSA_PKCS1_SHA256],
        signature_algorithms: [SignatureScheme::RSA_PSS_RSAE_SHA256] }
    ],
    [
      true,
      '-sigalgs RSA-PSS+SHA384',
      'rsa_rsa.crt',
      'rsa_rsa.key',
      { signature_algorithms_cert: [SignatureScheme::RSA_PKCS1_SHA256],
        signature_algorithms: [SignatureScheme::RSA_PSS_RSAE_SHA384] }
    ],
    [
      true,
      '-sigalgs RSA-PSS+SHA512',
      'rsa_rsa.crt',
      'rsa_rsa.key',
      { signature_algorithms_cert: [SignatureScheme::RSA_PKCS1_SHA256],
        signature_algorithms: [SignatureScheme::RSA_PSS_RSAE_SHA512] }
    ],
    [
      true,
      '-sigalgs ECDSA+SHA256',
      'rsa_secp256r1.crt',
      'rsa_secp256r1.key',
      { signature_algorithms_cert: [SignatureScheme::RSA_PKCS1_SHA256],
        signature_algorithms: [SignatureScheme::ECDSA_SECP256R1_SHA256] }
    ],
    [
      true,
      '-sigalgs ECDSA+SHA384',
      'rsa_secp384r1.crt',
      'rsa_secp384r1.key',
      { signature_algorithms_cert: [SignatureScheme::RSA_PKCS1_SHA256],
        signature_algorithms: [SignatureScheme::ECDSA_SECP384R1_SHA384] }
    ],
    [
      true,
      '-sigalgs ECDSA+SHA512',
      'rsa_secp521r1.crt',
      'rsa_secp521r1.key',
      { signature_algorithms_cert: [SignatureScheme::RSA_PKCS1_SHA256],
        signature_algorithms: [SignatureScheme::ECDSA_SECP521R1_SHA512] }
    ],
    [
      true,
      '-sigalgs RSA-PSS+SHA256',
      'rsa_rsassaPss.crt',
      'rsa_rsassaPss.key',
      { signature_algorithms_cert: [SignatureScheme::RSA_PSS_RSAE_SHA256],
        signature_algorithms: [SignatureScheme::RSA_PSS_RSAE_SHA256] }
    ],
    [
      false,
      '-sigalgs ECDSA+SHA256:ECDSA+SHA384:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256',
      'rsa_secp521r1.crt',
      'rsa_secp521r1.key',
      { signature_algorithms_cert: [SignatureScheme::RSA_PKCS1_SHA256],
        signature_algorithms: [SignatureScheme::ECDSA_SECP521R1_SHA512] }
    ],
    [
      true,
      '-record_padding 8446',
      'rsa_rsa.crt',
      'rsa_rsa.key',
      {}
    ],
    [
      true,
      '',
      'rsa_rsa.crt',
      'rsa_rsa.key',
      { key_share_groups: [] }
    ],
    [
      true,
      '-alpn http/1.0',
      'rsa_rsa.crt',
      'rsa_rsa.key',
      { alpn: ['http/1.0'] }
    ],
    [
      true,
      '',
      'rsa_rsa.crt',
      'rsa_rsa.key',
      { compatibility_mode: false }
    ]
  ]
  testcases.each do |normal, opt, crt, key, settings|
    context 'client interop' do
      before do
        cmd = 'openssl s_server ' \
              + "-cert /tmp/#{crt} " \
              + "-key /tmp/#{key} " \
              + '-tls1_3 ' \
              + '-www ' \
              + '-quiet ' \
              + "-accept #{PORT} " \
              + opt
        pid = spawn('docker run ' \
                    + "--volume #{FIXTURES_DIR}:/tmp " \
                    + "--publish #{PORT}:#{PORT} " \
                    + 'thekuwayama/openssl ' + cmd)
        Process.detach(pid)

        wait_to_listen('127.0.0.1', PORT)
      end

      let(:client) do
        hostname = 'localhost'
        @socket = TCPSocket.new(hostname, PORT)
        settings[:ca_file] = FIXTURES_DIR + '/rsa_ca.crt'
        Client.new(@socket, hostname, **settings)
      end

      after do
        @socket.close
        `docker ps -ql | xargs docker stop`
      end

      if normal
        it "should connect with openssl s_server ...#{opt}" do
          expect { client.connect }.to_not raise_error
          expect { client.write("GET / HTTP/1.0\r\n\r\n") }.to_not raise_error
          expect(client.read).to include "HTTP/1.0 200 ok\r\n"
          expect { client.close }.to_not raise_error
        end
      else # exceptions scenarios
        it "should NOT connect with openssl s_server ...#{opt}" do
          expect { client.connect }.to raise_error ErrorAlerts
        end
      end
    end
  end
end
