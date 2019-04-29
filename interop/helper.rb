# encoding: ascii-8bit
# frozen_string_literal: true

RSpec.configure(&:disable_monkey_patching!)

# rubocop: disable Style/MixinUsage
require 'openssl'
require 'tttls1.3'
include TTTLS13
include TTTLS13::Error
include TTTLS13::CipherSuite
include TTTLS13::SignatureScheme
include TTTLS13::Cryptograph
include TTTLS13::Message
include TTTLS13::Message::Extension
# rubocop: enable Style/MixinUsage
