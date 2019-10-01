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
  loop do
    s = TCPSocket.open(host, port) # check by TCP handshake
  rescue # rubocop: disable Style/RescueStandardError
    sleep(0.2)
    next
  else
    s.close
    break
  end
end
