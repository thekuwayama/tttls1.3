# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'helper'

hostname, port = (ARGV[0] || 'localhost:4433').split(':')
http_get = http_get(hostname)

settings_2nd = {
  ca_file: __dir__ + '/../tmp/ca.crt'
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
  ca_file: __dir__ + '/../tmp/ca.crt',
  process_new_session_ticket: process_new_session_ticket
}

[
  # Initial Handshake:
  settings_1st,
  # Subsequent Handshake:
  settings_2nd
].each do |settings|
  socket = TCPSocket.new(hostname, port)
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
end
