# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'helper'
HpkeSymmetricCipherSuite = \
  ECHConfig::ECHConfigContents::HpkeKeyConfig::HpkeSymmetricCipherSuite

hostname = 'crypto.cloudflare.com'
port = 443
ca_file = __dir__ + '/../tmp/ca.crt'
req = simple_http_request(hostname, '/cdn-cgi/trace')

rr = Resolv::DNS.new.getresources(
  hostname,
  Resolv::DNS::Resource::IN::HTTPS
)
settings_2nd = {
  ca_file: File.exist?(ca_file) ? ca_file : nil,
  alpn: ['http/1.1'],
  ech_config: rr.first.svc_params['ech'].echconfiglist.first,
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
  process_new_session_ticket: process_new_session_ticket,
  ech_config: rr.first.svc_params['ech'].echconfiglist.first,
  ech_hpke_cipher_suites: [
    HpkeSymmetricCipherSuite.new(
      HpkeSymmetricCipherSuite::HpkeKdfId.new(
        TTTLS13::Hpke::KdfId::HKDF_SHA256
      ),
      HpkeSymmetricCipherSuite::HpkeAeadId.new(
        TTTLS13::Hpke::AeadId::AES_128_GCM
      )
    )
  ],
  sslkeylogfile: '/tmp/sslkeylogfile.log'
}

[
  # Initial Handshake:
  settings_1st,
  # Subsequent Handshake:
  settings_2nd
].each do |settings|
  socket = TCPSocket.new(hostname, port)
  client = TTTLS13::Client.new(socket, hostname, **settings)
  client.connect
  client.write(req)
  print recv_http_response(client)
  client.close unless client.eof?
  socket.close
end
