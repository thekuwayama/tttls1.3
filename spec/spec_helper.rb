RSpec.configure(&:disable_monkey_patching!)

# rubocop: disable Style/MixinUsage
require 'tls13'
include TLS13
include TLS13::Message
include TLS13::Cryptograph
# rubocop: enable Style/MixinUsage

RECORD_HEADER = '16 03 03 00 00'.split.map(&:hex).freeze

# https://tools.ietf.org/html/rfc8448#page-3
