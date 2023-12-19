# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'helper'
HpkeSymmetricCipherSuite = \
  ECHConfig::ECHConfigContents::HpkeKeyConfig::HpkeSymmetricCipherSuite

hostname = 'crypto.cloudflare.com'
port = 443
ca_file = __dir__ + '/../tmp/ca.crt'

socket = TCPSocket.new(hostname, port)
settings = {
  ca_file: File.exist?(ca_file) ? ca_file : nil,
  alpn: ['http/1.1'],
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
client = TTTLS13::Client.new(socket, hostname, **settings)
client.connect

print client.retry_configs

client.close unless client.eof?
socket.close