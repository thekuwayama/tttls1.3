# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'helper'

uri = URI.parse(ARGV[0] || 'https://localhost:4433')
ca_file = __dir__ + '/../tmp/ca.crt'
req = simple_http_request(uri.host, uri.path)
ech_config = if ARGV.length > 1
               parse_echconfigs_pem(File.open(ARGV[1]).read).first
             else
               resolve_echconfig(uri.host)
             end

socket = TCPSocket.new(uri.host, uri.port)
settings = {
  ca_file: File.exist?(ca_file) ? ca_file : nil,
  alpn: ['http/1.1'],
  ech_config: ech_config,
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
