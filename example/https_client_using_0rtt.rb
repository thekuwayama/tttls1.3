# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'helper'

hostname, port = (ARGV[0] || 'localhost:4433').split(':')
ca_file = __dir__ + '/../tmp/ca.crt'
req = simple_http_request(hostname)

settings_2nd = {
  ca_file: File.exist?(ca_file) ? ca_file : nil,
  alpn: ['http/1.1']
}
process_new_session_ticket = proc do |nst, rms, cs|
  return if Time.now.to_i - nst.timestamp > nst.ticket_lifetime

  settings_2nd[:ticket] = nst.ticket
  settings_2nd[:resumption_master_secret] = rms
  settings_2nd[:psk_cipher_suite] = cs
  settings_2nd[:ticket_nonce] = nst.ticket_nonce
  settings_2nd[:ticket_age_add] = nst.ticket_age_add
  settings_2nd[:ticket_timestamp] = nst.timestamp
end
settings_1st = {
  ca_file: FileTest.exists?(ca_file) ? ca_file : nil,
  alpn: ['http/1.1'],
  process_new_session_ticket: process_new_session_ticket
}

succeed_early_data = false

[
  # Initial Handshake:
  settings_1st,
  # Subsequent Handshake:
  settings_2nd
].each_with_index do |settings, i|
  socket = TCPSocket.new(hostname, port)
  client = TTTLS13::Client.new(socket, hostname, settings)

  # send message using early data; 0-RTT
  client.early_data(req) if i == 1 && settings.include?(:ticket)
  client.connect
  # send message after Simple 1-RTT Handshake
  client.write(req) if i.zero? || !client.succeed_early_data?
  print recv_http_response(client)
  client.close

  succeed_early_data = client.succeed_early_data?
end

puts "\n" + '-' * 10
puts "early data of 2nd handshake: #{succeed_early_data}"
