# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'helper'

uri = URI.parse(ARGV[0] || 'https://localhost:4433')
ca_file = __dir__ + '/../tmp/ca.crt'
req = simple_http_request(uri.host, uri.path)
ech_config = if ARGV.length > 1
               parse_echconfigs_pem(File.open(ARGV[1]).read).first
             else
               resolve_echconfig(uri.host)
             end

settings = {
  ca_file: File.exist?(ca_file) ? ca_file : nil,
  alpn: ['http/1.1'],
  ech_config:,
  ech_hpke_cipher_suites:
    TTTLS13::STANDARD_CLIENT_ECH_HPKE_SYMMETRIC_CIPHER_SUITES,
  sslkeylogfile: '/tmp/sslkeylogfile.log'
}

# Initial Handshake:
socket = TCPSocket.new(uri.host, uri.port)
client = TTTLS13::Client.new(socket, uri.host, **settings)
client.connect

if client.rejected_ech?
  retry_config = client.retry_configs.first
  client.close unless client.eof?
  socket.close
  raise 'failed to authenticate retry_configs' if retry_config.nil?

  ech_auth_type = ECHConfig::ECHConfigContents::Extensions::ECHAuth::TYPE
  ech_auth = retry_config.echconfig_contents.extensions[ech_auth_type]
  settings[:ech_config] = ech_auth&.disable? ? nil : retry_config

  # Subsequent Handshake:
  socket = TCPSocket.new(uri.host, uri.port)
  client = TTTLS13::Client.new(socket, uri.host, **settings)
  client.connect
end

client.write(req)

print recv_http_response(client)
client.close unless client.eof?
socket.close
