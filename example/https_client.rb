# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'helper'

hostname, port = (ARGV[0] || 'localhost:4433').split(':')
http_get = http_get(hostname)

socket = TCPSocket.new(hostname, port)
settings = { ca_file: __dir__ + '/../tmp/ca.crt' }
client = TTTLS13::Client.new(socket, hostname, settings)
client.connect
client.write(http_get)

# status line, header
buffer = ''
buffer += client.read until buffer.include?("\r\n\r\n")
print header = buffer.split("\r\n\r\n").first
# header; Content-Length
cl_line = header.split("\r\n").find { |s| s.match(/Content-Length:/i) }

# body
unless cl_line.nil?
  cl = cl_line.split(':').last.to_i
  print buffer = buffer.split("\r\n\r\n")[1..].join
  while buffer.length < cl
    print s = client.read
    buffer += s
  end
end

client.close
