# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'helper'

TMP_DIR = __dir__ + '/../tmp'
tcpserver = TCPServer.open(4433)

RSpec.describe Server do
  # testcases
  # opt [String] openssl s_client options
  # settings [Hash] TTTLS13::Client settins
  [
    [
      '-groups P-256:P-384:P-521 ' \
      + '-ciphersuites TLS_AES_256_GCM_SHA384 ',
      cipher_suites: [CipherSuite::TLS_AES_256_GCM_SHA384]
    ],
    [
      '-groups P-256:P-384:P-521 ' \
      + '-ciphersuites TLS_CHACHA20_POLY1305_SHA256',
      cipher_suites: [CipherSuite::TLS_CHACHA20_POLY1305_SHA256]
    ],
    [
      '-groups P-256:P-384:P-521 ' \
      + '-ciphersuites TLS_AES_128_GCM_SHA256',
      cipher_suites: [CipherSuite::TLS_AES_128_GCM_SHA256]
    ],
    [
      '-groups P-256',
      supported_groups: [NamedGroup::SECP256R1]
    ],
    [
      '-groups P-384',
      supported_groups: [NamedGroup::SECP384R1]
    ],
    [
      '-groups P-521',
      supported_groups: [NamedGroup::SECP521R1]
    ],
    [
      '-groups P-256:P-384:P-521 ' \
      + '-sigalgs RSA-PSS+SHA256',
      signature_algorithms_cert: [SignatureScheme::RSA_PKCS1_SHA256],
      signature_algorithms: [SignatureScheme::RSA_PSS_RSAE_SHA256]
    ],
    [
      '-groups P-256:P-384:P-521 ' \
      + '-sigalgs RSA-PSS+SHA384',
      signature_algorithms_cert: [SignatureScheme::RSA_PKCS1_SHA256],
      signature_algorithms: [SignatureScheme::RSA_PSS_RSAE_SHA384]
    ],
    [
      '-groups P-256:P-384:P-521 ' \
      + '-sigalgs RSA-PSS+SHA512',
      signature_algorithms_cert: [SignatureScheme::RSA_PKCS1_SHA256],
      signature_algorithms: [SignatureScheme::RSA_PSS_RSAE_SHA512]
    ],
    [
      '-groups P-256:P-384:P-521 ' \
      '-record_padding 8446',
      {}
    ]
  ].each do |opt, settings|
    context 'server interop' do
      let(:server) do
        @socket = tcpserver.accept
        settings[:crt_file] = TMP_DIR + '/server.crt'
        settings[:key_file] = TMP_DIR + '/server.key'
        Server.new(@socket, settings)
      end

      let(:client) do
        ip = IPSocket.getaddress(Socket.gethostname)
        cmd = 'echo -n ping | openssl s_client ' \
              + '-connect local:4433 ' \
              + '-tls1_3 ' \
              + '-CAfile /tmp/ca.crt ' \
              + '-servername localhost ' \
              + '-quiet ' \
              + opt
        "docker run -v #{TMP_DIR}:/tmp --add-host=local:#{ip} -it openssl " \
        + "sh -c \"#{cmd}\" 2>&1 >/dev/null"
      end

      after do
        @socket.close
        `docker ps -ql | xargs docker stop`
      end

      it "should accept request from openssl s_client ...#{opt}" do
        spawn('sleep 2; ' + client)
        expect { server.accept }.to_not raise_error
        expect(server.read).to include 'ping'
        expect { server.write('pong') }.to_not raise_error
        expect { server.close }.to_not raise_error
      end
    end
  end
end
