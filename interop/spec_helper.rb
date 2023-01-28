# encoding: ascii-8bit
# frozen_string_literal: true

RSpec.configure(&:disable_monkey_patching!)

# rubocop: disable Style/MixinUsage
require 'tttls1.3'
include TTTLS13
include TTTLS13::CipherSuite
include TTTLS13::SignatureScheme
include TTTLS13::Message::Extension
include TTTLS13::Error
# rubocop: enable Style/MixinUsage

def wait_to_listen(host, port)
  10.times do
    soc = TCPSocket.open(host, port)
    ctx = OpenSSL::SSL::SSLContext.new
    ctx.max_version = OpenSSL::SSL::TLS1_3_VERSION
    ssl = OpenSSL::SSL::SSLSocket.new(soc, ctx)
    ssl.sync_close = true
    ssl.connect
  rescue => e # rubocop: disable Style/RescueStandardError
    p e
    soc&.close
    sleep(0.5)
    next
  else
    ssl.close
    break
  end
end
