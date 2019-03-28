# frozen_string_literal: true

require_relative 'helper'

hostname, port = (ARGV[0] || 'localhost:4433').split(':')
socket = TCPSocket.new(hostname, port)
client = TLS13::Client.new(socket)
client.hostname = hostname
client.connect
http_get = <<~BIN
  GET / HTTP/1.1\r
  Host: #{hostname}\r
  User-Agent: https_client\r
  Accept: */*\r
  \r
BIN
client.write(http_get)
puts client.read
