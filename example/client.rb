# frozen_string_literal: true

require_relative 'helper'

socket = TCPSocket.new('localhost', 443)
client = TLS13::Client.new(socket)
client.hostname = 'test-server'
client.connect
