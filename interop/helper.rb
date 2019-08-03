# frozen_string_literal: true

# rubocop: disable Style/MixinUsage
require 'tttls1.3'
require 'rspec/retry'

include TTTLS13
include TTTLS13::CipherSuite
include TTTLS13::SignatureScheme
include TTTLS13::Message::Extension
include TTTLS13::Error
# rubocop: enable Style/MixinUsage

INTERVAL = 0.2

def wait_to_listen(port)
  sleep(INTERVAL) while `lsof -ni :#{port}`.empty?
end

RSpec.configure do |config|
  config.verbose_retry = true
  config.default_retry_count = 2
  config.display_try_failure_messages = true
  config.default_sleep_interval = INTERVAL * 2
  config.clear_lets_on_failure = false
end
