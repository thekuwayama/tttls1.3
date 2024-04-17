# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'helper'

uri = URI.parse(ARGV[0] || 'https://localhost:4433')
ca_file = __dir__ + '/../tmp/ca.crt'
req = simple_http_request(uri.host, uri.path)
ech_config = if ARGV.length > 1
               parse_echconfigs_pem(File.open(ARGV[1]).read).first
             else
               rr = Resolv::DNS.new.getresources(
                 uri.host,
                 Resolv::DNS::Resource::IN::HTTPS
               )
               rr.first.svc_params['ech'].echconfiglist.first
             end

settings_2nd = {
  ca_file: File.exist?(ca_file) ? ca_file : nil,
  alpn: ['http/1.1'],
  ech_config: ech_config,
  ech_hpke_cipher_suites:
    TTTLS13::STANDARD_CLIENT_ECH_HPKE_SYMMETRIC_CIPHER_SUITES,
  sslkeylogfile: '/tmp/sslkeylogfile.log'
}
process_new_session_ticket = lambda do |nst, rms, cs|
  return if Time.now.to_i - nst.timestamp > nst.ticket_lifetime

  settings_2nd[:ticket] = nst.ticket
  settings_2nd[:resumption_main_secret] = rms
  settings_2nd[:psk_cipher_suite] = cs
  settings_2nd[:ticket_nonce] = nst.ticket_nonce
  settings_2nd[:ticket_age_add] = nst.ticket_age_add
  settings_2nd[:ticket_timestamp] = nst.timestamp
end
settings_1st = {
  ca_file: File.exist?(ca_file) ? ca_file : nil,
  alpn: ['http/1.1'],
  ech_config: ech_config,
  ech_hpke_cipher_suites:
    TTTLS13::STANDARD_CLIENT_ECH_HPKE_SYMMETRIC_CIPHER_SUITES,
  process_new_session_ticket: process_new_session_ticket,
  sslkeylogfile: '/tmp/sslkeylogfile.log'
}

[
  # Initial Handshake:
  settings_1st,
  # Subsequent Handshake:
  settings_2nd
].each do |settings|
  socket = TCPSocket.new(uri.host, uri.port)
  client = TTTLS13::Client.new(socket, uri.host, **settings)
  client.connect
  client.write(req)

  print recv_http_response(client)
  client.close unless client.eof?
  socket.close
end