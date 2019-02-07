RSpec.configure(&:disable_monkey_patching!)

# rubocop: disable Style/MixinUsage
require 'tls13'
include TLS13
include TLS13::Message
# rubocop: enable Style/MixinUsage
