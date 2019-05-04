# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'helper'

TMP_DIR = __dir__ + '/../tmp'

RSpec.describe Client do
  # testcases
  [
    [
      ' -ciphersuites TLS_AES_256_GCM_SHA384',
      cipher_suites: [CipherSuite::TLS_AES_256_GCM_SHA384]
    ],
    [
      ' -ciphersuites TLS_CHACHA20_POLY1305_SHA256',
      cipher_suites: [CipherSuite::TLS_CHACHA20_POLY1305_SHA256]
    ],
    [
      ' -ciphersuites TLS_AES_128_GCM_SHA256',
      cipher_suites: [CipherSuite::TLS_AES_128_GCM_SHA256]
    ],
    [
      ' -groups P-256',
      supported_groups: [NamedGroup::SECP256R1]
    ],
    [
      ' -groups P-384',
      supported_groups: [NamedGroup::SECP384R1]
    ],
    [
      ' -groups P-521',
      supported_groups: [NamedGroup::SECP521R1]
    ],
    [
      ' -sigalgs RSA-PSS+SHA256',
      signature_algorithms_cert: [SignatureScheme::RSA_PKCS1_SHA256],
      signature_algorithms: [SignatureScheme::RSA_PSS_RSAE_SHA256]
    ],
    [
      ' -sigalgs RSA-PSS+SHA384',
      signature_algorithms_cert: [SignatureScheme::RSA_PKCS1_SHA256],
      signature_algorithms: [SignatureScheme::RSA_PSS_RSAE_SHA384]
    ],
    [
      ' -sigalgs RSA-PSS+SHA512',
      signature_algorithms_cert: [SignatureScheme::RSA_PKCS1_SHA256],
      signature_algorithms: [SignatureScheme::RSA_PSS_RSAE_SHA512]
    ],
    [
      ' -record_padding 8446',
      {}
    ]
  ].each do |opt, settings|
    context 'client interop' do
      before do
        cmd = "docker run -v #{TMP_DIR}:/tmp -p 4433:4433 -it openssl " \
              + 'openssl s_server ' \
              + '-cert /tmp/server.crt ' \
              + '-key /tmp/server.key ' \
              + '-tls1_3 ' \
              + '-www ' \
              + '-quiet ' \
              + opt
        pid = spawn(cmd)
        Process.detach(pid)

        sleep(2) # waiting for openssl s_server
      end

      let(:client) do
        hostname = 'localhost'
        @socket = TCPSocket.new(hostname, 4433)
        settings[:ca_file] = TMP_DIR + '/ca.crt'
        Client.new(@socket, hostname, settings)
      end

      after do
        @socket.close
        `docker ps -ql | xargs docker stop`
      end

      it "should connect with openssl s_server ...#{opt}" do
        expect { client.connect }.to_not raise_error
        expect { client.write("GET / HTTP/1.0\r\n\r\n") }.to_not raise_error
        expect(client.read).to include "HTTP/1.0 200 ok\r\n"
        expect { client.close }.to_not raise_error
      end
    end
  end
end
