# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'helper'
require 'svcb_rr_patch'

HpkeSymmetricCipherSuite = \
  ECHConfig::ECHConfigContents::HpkeKeyConfig::HpkeSymmetricCipherSuite
hostname = 'crypto.cloudflare.com'
port = 443
ca_file = __dir__ + '/../tmp/ca.crt'
req = simple_http_request(hostname, '/cdn-cgi/trace')

rr = Resolv::DNS.new.getresources(
  hostname,
  Resolv::DNS::Resource::IN::HTTPS
)
socket = TCPSocket.new(hostname, port)
settings = {
  ca_file: File.exist?(ca_file) ? ca_file : nil,
  alpn: ['http/1.1'],
  ech_config: rr.first.svc_params['ech'].echconfiglist.first,
  ech_hpke_cipher_suites: [
    HpkeSymmetricCipherSuite.new(
      HpkeSymmetricCipherSuite::HpkeKdfId.new(1),
      HpkeSymmetricCipherSuite::HpkeAeadId.new(1)
    )
  ],
  sslkeylogfile: '/tmp/sslkeylogfile.log'
}
client = TTTLS13::Client.new(socket, hostname, **settings)
client.connect
client.write(req)

print recv_http_response(client)
client.close unless client.eof?
socket.close
