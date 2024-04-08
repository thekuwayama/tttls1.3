# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'helper'

uri = URI.parse(ARGV[0] || 'https://localhost:4433')
ca_file = __dir__ + '/../tmp/ca.crt'

socket = TCPSocket.new(uri.host, uri.port)
settings = {
  ca_file: File.exist?(ca_file) ? ca_file : nil,
  alpn: ['http/1.1'],
  ech_hpke_cipher_suites:
    TTTLS13::STANDARD_CLIENT_ECH_HPKE_SYMMETRIC_CIPHER_SUITES,
  sslkeylogfile: '/tmp/sslkeylogfile.log'
}
client = TTTLS13::Client.new(socket, uri.host, **settings)
client.connect

print client.retry_configs if client.rejected_ech?
client.close unless client.eof?
socket.close
