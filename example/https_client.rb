# frozen_string_literal: true

require_relative 'helper'

hostname, port = (ARGV[0] || 'localhost:4433').split(':')
socket = TCPSocket.new(hostname, port)
client = TLS13::Client.new(socket)
client.hostname = hostname
client.crt_file = __dir__ + '/../tmp/ca.crt'
client.connect
http_get = <<~BIN
  GET / HTTP/1.1\r
  Host: #{hostname}\r
  User-Agent: https_client\r
  Accept: */*\r
  \r
BIN
client.write(http_get)

# status line, header
buffer = ''
buffer += client.read until buffer.include?("\r\n\r\n")
print header = buffer.split("\r\n\r\n").first
# header; Content-Length
cl_line = header.split("\r\n").find { |s| s.match(/Content-Length:/i) }
cl = cl_line.split(':').last.to_i

# body
print buffer = buffer.split("\r\n\r\n")[1..].join
while buffer.length < cl
  print s = client.read
  buffer += s
end
