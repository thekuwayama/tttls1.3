# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'helper'

FIXTURES_DIR = __dir__ + '/../spec/fixtures'
PORT = 4433

tcpserver = TCPServer.open(PORT)

RSpec.describe Server do
  # testcases
  # normal [Boolean] Is this nominal scenarios?
  # opt [String] openssl s_client options
  # crt [String] server crt file path
  # key [String] server key file path
  # settings [Hash] TTTLS13::Client settins
  [
    # rubocop: disable Metrics/LineLength
    [
      true,
      '-groups P-256:P-384:P-521 -ciphersuites TLS_AES_256_GCM_SHA384',
      FIXTURES_DIR + '/rsa_rsa.crt',
      FIXTURES_DIR + '/rsa_rsa.key',
      cipher_suites: [CipherSuite::TLS_AES_256_GCM_SHA384]
    ],
    [
      true,
      '-groups P-256:P-384:P-521 -ciphersuites TLS_CHACHA20_POLY1305_SHA256',
      FIXTURES_DIR + '/rsa_rsa.crt',
      FIXTURES_DIR + '/rsa_rsa.key',
      cipher_suites: [CipherSuite::TLS_CHACHA20_POLY1305_SHA256]
    ],
    [
      true,
      '-groups P-256:P-384:P-521 -ciphersuites TLS_AES_128_GCM_SHA256',
      FIXTURES_DIR + '/rsa_rsa.crt',
      FIXTURES_DIR + '/rsa_rsa.key',
      cipher_suites: [CipherSuite::TLS_AES_128_GCM_SHA256]
    ],
    [
      false,
      '-groups P-256:P-384:P-521 -ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
      FIXTURES_DIR + '/rsa_rsa.crt',
      FIXTURES_DIR + '/rsa_rsa.key',
      cipher_suites: [CipherSuite::TLS_AES_128_GCM_SHA256]
    ],
    [
      true,
      '-groups P-256',
      FIXTURES_DIR + '/rsa_rsa.crt',
      FIXTURES_DIR + '/rsa_rsa.key',
      supported_groups: [NamedGroup::SECP256R1]
    ],
    [
      true,
      '-groups P-384',
      FIXTURES_DIR + '/rsa_rsa.crt',
      FIXTURES_DIR + '/rsa_rsa.key',
      supported_groups: [NamedGroup::SECP384R1]
    ],
    [
      true,
      '-groups P-521',
      FIXTURES_DIR + '/rsa_rsa.crt',
      FIXTURES_DIR + '/rsa_rsa.key',
      supported_groups: [NamedGroup::SECP521R1]
    ],
    [
      false,
      '-groups P-256:P-384',
      FIXTURES_DIR + '/rsa_rsa.crt',
      FIXTURES_DIR + '/rsa_rsa.key',
      supported_groups: [NamedGroup::SECP521R1]
    ],
    [
      true,
      '-groups P-256:P-384:P-521 -sigalgs RSA-PSS+SHA256',
      FIXTURES_DIR + '/rsa_rsa.crt',
      FIXTURES_DIR + '/rsa_rsa.key',
      signature_algorithms_cert: [SignatureScheme::RSA_PKCS1_SHA256],
      signature_algorithms: [SignatureScheme::RSA_PSS_RSAE_SHA256]
    ],
    [
      true,
      '-groups P-256:P-384:P-521 -sigalgs RSA-PSS+SHA384',
      FIXTURES_DIR + '/rsa_rsa.crt',
      FIXTURES_DIR + '/rsa_rsa.key',
      signature_algorithms_cert: [SignatureScheme::RSA_PKCS1_SHA256],
      signature_algorithms: [SignatureScheme::RSA_PSS_RSAE_SHA384]
    ],
    [
      true,
      '-groups P-256:P-384:P-521 -sigalgs RSA-PSS+SHA512',
      FIXTURES_DIR + '/rsa_rsa.crt',
      FIXTURES_DIR + '/rsa_rsa.key',
      signature_algorithms_cert: [SignatureScheme::RSA_PKCS1_SHA256],
      signature_algorithms: [SignatureScheme::RSA_PSS_RSAE_SHA512]
    ],
    [
      true,
      '-groups P-256:P-384:P-521 -sigalgs ECDSA+SHA256',
      FIXTURES_DIR + '/rsa_secp256r1.crt',
      FIXTURES_DIR + '/rsa_secp256r1.key',
      signature_algorithms_cert: [SignatureScheme::RSA_PKCS1_SHA256],
      signature_algorithms: [SignatureScheme::ECDSA_SECP256R1_SHA256]
    ],
    [
      true,
      '-groups P-256:P-384:P-521 -sigalgs ECDSA+SHA384',
      FIXTURES_DIR + '/rsa_secp384r1.crt',
      FIXTURES_DIR + '/rsa_secp384r1.key',
      signature_algorithms_cert: [SignatureScheme::RSA_PKCS1_SHA256],
      signature_algorithms: [SignatureScheme::ECDSA_SECP384R1_SHA384]
    ],
    [
      true,
      '-groups P-256:P-384:P-521 -sigalgs ECDSA+SHA512',
      FIXTURES_DIR + '/rsa_secp521r1.crt',
      FIXTURES_DIR + '/rsa_secp521r1.key',
      signature_algorithms_cert: [SignatureScheme::RSA_PKCS1_SHA256],
      signature_algorithms: [SignatureScheme::ECDSA_SECP521R1_SHA512]
    ],
    [
      true,
      '-groups P-256:P-384:P-521 -sigalgs RSA-PSS+SHA256',
      FIXTURES_DIR + '/rsa_rsassaPss.crt',
      FIXTURES_DIR + '/rsa_rsassaPss.key',
      signature_algorithms_cert: [SignatureScheme::RSA_PSS_RSAE_SHA256],
      signature_algorithms: [SignatureScheme::RSA_PSS_RSAE_SHA256]
    ],
    [
      false,
      '-groups P-256:P-384:P-521 -sigalgs ECDSA+SHA256:ECDSA+SHA384:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256',
      FIXTURES_DIR + '/rsa_rsa.crt',
      FIXTURES_DIR + '/rsa_rsa.key',
      signature_algorithms_cert: [SignatureScheme::RSA_PKCS1_SHA256],
      signature_algorithms: [SignatureScheme::ECDSA_SECP521R1_SHA512]
    ],
    [
      true,
      '-groups P-256:P-384:P-521 -record_padding 8446',
      FIXTURES_DIR + '/rsa_rsa.crt',
      FIXTURES_DIR + '/rsa_rsa.key',
      {}
    ]
    # rubocop: enable Metrics/LineLength
  ].each do |normal, opt, crt, key, settings|
    context 'server interop' do
      let(:server) do
        @socket = tcpserver.accept
        settings[:crt_file] = crt
        settings[:key_file] = key
        Server.new(@socket, settings)
      end

      let(:client) do
        wait_to_listen(PORT)

        ip = Socket.ip_address_list.find(&:ipv4_private?).ip_address
        cmd = 'echo -n ping | openssl s_client ' \
              + "-connect local:#{PORT} " \
              + '-tls1_3 ' \
              + '-CAfile /tmp/rsa_ca.crt ' \
              + '-servername localhost ' \
              + '-quiet ' \
              + opt
        'docker run ' \
        + "--volume #{FIXTURES_DIR}:/tmp " \
        + "--add-host=local:#{ip} -it openssl " \
        + "sh -c \"#{cmd}\" 2>&1 >/dev/null"
      end

      after do
        @socket.close
        `docker ps -ql | xargs docker stop`
      end

      if normal
        it "should accept request from openssl s_client ...#{opt}" do
          spawn(client)
          expect { server.accept }.to_not raise_error
          expect(server.read).to include 'ping'
          expect { server.write('pong') }.to_not raise_error
          expect { server.close }.to_not raise_error
        end
      else # exceptions scenarios
        it "should NOT accept request from openssl s_client ...#{opt}" do
          spawn(client)
          expect { server.accept }.to raise_error ErrorAlerts
        end
      end
    end
  end
end
