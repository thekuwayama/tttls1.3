# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'helper'

uri = URI.parse(ARGV[0] || 'https://localhost:4433')
ca_file = __dir__ + '/../tmp/ca.crt'
req = simple_http_request(uri.host, uri.path)

socket = TCPSocket.new(uri.host, uri.port)
process_certificate_status = lambda do |res, cert, chain|
  puts 'stapled OCSPResponse: '
  puts res.basic.status.pretty_inspect unless res.nil?
  puts '-' * 10

  TTTLS13::Client.softfail_check_certificate_status(res, cert, chain)
end
settings = {
  ca_file: File.exist?(ca_file) ? ca_file : nil,
  alpn: ['http/1.1'],
  check_certificate_status: true,
  process_certificate_status:,
  sslkeylogfile: '/tmp/sslkeylogfile.log'
}
client = TTTLS13::Client.new(socket, uri.host, **settings)
client.connect
client.write(req)

print recv_http_response(client)
client.close unless client.eof?
socket.close
