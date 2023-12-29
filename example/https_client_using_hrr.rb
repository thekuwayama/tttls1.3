# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'helper'

uri = URI.parse(ARGV[0] || 'https://localhost:4433')
ca_file = __dir__ + '/../tmp/ca.crt'
req = simple_http_request(uri.host, uri.path)

socket = TCPSocket.new(uri.host, uri.port)
settings = {
  ca_file: File.exist?(ca_file) ? ca_file : nil,
  key_share_groups: [], # empty KeyShareClientHello.client_shares
  alpn: ['http/1.1']
}
client = TTTLS13::Client.new(socket, uri.host, **settings)
client.connect
client.write(req)

print recv_http_response(client)
client.close unless client.eof?
socket.close
