# frozen_string_literal: true

require_relative 'helper'

hostname, port = (ARGV[0] || 'localhost:443').split(':')
socket = TCPSocket.new(hostname, port)
client = TLS13::Client.new(socket)
client.hostname = hostname
client.connect
