# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'helper'

uri = URI.parse(ARGV[0] || 'https://localhost:4433')
ca_file = __dir__ + '/../tmp/ca.crt'
req = simple_http_request(uri.host, uri.path)

rr = Resolv::DNS.new.getresources(
  uri.host,
  Resolv::DNS::Resource::IN::HTTPS
)
socket = TCPSocket.new(uri.host, uri.port)
settings = {
  ca_file: File.exist?(ca_file) ? ca_file : nil,
  alpn: ['http/1.1'],
  ech_config: rr.first.svc_params['ech'].echconfiglist.first,
  ech_hpke_cipher_suites:
    TTTLS13::STANDARD_CLIENT_ECH_HPKE_SYMMETRIC_CIPHER_SUITES,
  sslkeylogfile: '/tmp/sslkeylogfile.log'
}
client = TTTLS13::Client.new(socket, uri.host, **settings)
client.connect
client.write(req)

print recv_http_response(client)
client.close unless client.eof?
socket.close
