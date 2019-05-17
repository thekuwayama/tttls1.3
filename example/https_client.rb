# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'helper'

hostname, port = (ARGV[0] || 'localhost:4433').split(':')
req = simple_http_request(hostname)

socket = TCPSocket.new(hostname, port)
settings = { ca_file: __dir__ + '/../tmp/ca.crt' }
client = TTTLS13::Client.new(socket, hostname, settings)
client.connect
client.write(req)
print recv_http_response(client)
client.close
