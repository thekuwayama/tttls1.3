# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'helper'

FIXTURES_DIR = __dir__ + '/../spec/fixtures'

RSpec.describe Client do
  # testcases
  # normal [Boolean] Is this nominal scenarios?
  # opt [String] openssl s_server options
  # crt [String] server crt file path
  # key [String] server key file path
  # settings [Hash] TTTLS13::Server settings
  [
    # rubocop: disable Metrics/LineLength
    [
      true,
      '-ciphersuites TLS_AES_256_GCM_SHA384',
      'rsa_rsa.crt',
      'rsa_rsa.key',
      cipher_suites: [CipherSuite::TLS_AES_256_GCM_SHA384]
    ],
    [
      true,
      '-ciphersuites TLS_CHACHA20_POLY1305_SHA256',
      'rsa_rsa.crt',
      'rsa_rsa.key',
      cipher_suites: [CipherSuite::TLS_CHACHA20_POLY1305_SHA256]
    ],
    [
      true,
      '-ciphersuites TLS_AES_128_GCM_SHA256',
      'rsa_rsa.crt',
      'rsa_rsa.key',
      cipher_suites: [CipherSuite::TLS_AES_128_GCM_SHA256]
    ],
    [
      false,
      '-ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
      'rsa_rsa.crt',
      'rsa_rsa.key',
      cipher_suites: [CipherSuite::TLS_AES_128_GCM_SHA256]
    ],
    [
      true,
      '-groups P-256',
      'rsa_rsa.crt',
      'rsa_rsa.key',
      supported_groups: [NamedGroup::SECP256R1]
    ],
    [
      true,
      '-groups P-384',
      'rsa_rsa.crt',
      'rsa_rsa.key',
      supported_groups: [NamedGroup::SECP384R1]
    ],
    [
      true,
      '-groups P-521',
      'rsa_rsa.crt',
      'rsa_rsa.key',
      supported_groups: [NamedGroup::SECP521R1]
    ],
    [
      false,
      '-groups P-256:P-384',
      'rsa_rsa.crt',
      'rsa_rsa.key',
      supported_groups: [NamedGroup::SECP521R1]
    ],
    [
      true,
      '-sigalgs RSA-PSS+SHA256',
      'rsa_rsa.crt',
      'rsa_rsa.key',
      signature_algorithms_cert: [SignatureScheme::RSA_PKCS1_SHA256],
      signature_algorithms: [SignatureScheme::RSA_PSS_RSAE_SHA256]
    ],
    [
      true,
      '-sigalgs RSA-PSS+SHA384',
      'rsa_rsa.crt',
      'rsa_rsa.key',
      signature_algorithms_cert: [SignatureScheme::RSA_PKCS1_SHA256],
      signature_algorithms: [SignatureScheme::RSA_PSS_RSAE_SHA384]
    ],
    [
      true,
      '-sigalgs RSA-PSS+SHA512',
      'rsa_rsa.crt',
      'rsa_rsa.key',
      signature_algorithms_cert: [SignatureScheme::RSA_PKCS1_SHA256],
      signature_algorithms: [SignatureScheme::RSA_PSS_RSAE_SHA512]
    ],
    [
      true,
      '-sigalgs ECDSA+SHA256',
      'rsa_secp256r1.crt',
      'rsa_secp256r1.key',
      signature_algorithms_cert: [SignatureScheme::RSA_PKCS1_SHA256],
      signature_algorithms: [SignatureScheme::ECDSA_SECP256R1_SHA256]
    ],
    [
      true,
      '-sigalgs ECDSA+SHA384',
      'rsa_secp384r1.crt',
      'rsa_secp384r1.key',
      signature_algorithms_cert: [SignatureScheme::RSA_PKCS1_SHA256],
      signature_algorithms: [SignatureScheme::ECDSA_SECP384R1_SHA384]
    ],
    [
      true,
      '-sigalgs ECDSA+SHA512',
      'rsa_secp521r1.crt',
      'rsa_secp521r1.key',
      signature_algorithms_cert: [SignatureScheme::RSA_PKCS1_SHA256],
      signature_algorithms: [SignatureScheme::ECDSA_SECP521R1_SHA512]
    ],
    [
      true,
      '-sigalgs RSA-PSS+SHA256',
      'rsa_rsassaPss.crt',
      'rsa_rsassaPss.key',
      signature_algorithms_cert: [SignatureScheme::RSA_PSS_RSAE_SHA256],
      signature_algorithms: [SignatureScheme::RSA_PSS_RSAE_SHA256]
    ],
    [
      false,
      '-sigalgs ECDSA+SHA256:ECDSA+SHA384:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256',
      'rsa_secp521r1.crt',
      'rsa_secp521r1.key',
      signature_algorithms_cert: [SignatureScheme::RSA_PKCS1_SHA256],
      signature_algorithms: [SignatureScheme::ECDSA_SECP521R1_SHA512]
    ],
    [
      true,
      '-record_padding 8446',
      'rsa_rsa.crt',
      'rsa_rsa.key',
      {}
    ]
    # rubocop: enable Metrics/LineLength
  ].each do |normal, opt, crt, key, settings|
    context 'client interop' do
      before do
        cmd = "docker run -v #{FIXTURES_DIR}:/tmp -p 4433:4433 -it openssl " \
              + 'openssl s_server ' \
              + "-cert /tmp/#{crt} " \
              + "-key /tmp/#{key} " \
              + '-tls1_3 ' \
              + '-www ' \
              + '-quiet ' \
              + opt
        pid = spawn(cmd)
        Process.detach(pid)

        sleep(2.5) # waiting for openssl s_server
      end

      let(:client) do
        hostname = 'localhost'
        @socket = TCPSocket.new(hostname, 4433)
        settings[:ca_file] = FIXTURES_DIR + '/rsa_ca.crt'
        Client.new(@socket, hostname, settings)
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
