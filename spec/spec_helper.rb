# encoding: ascii-8bit
# frozen_string_literal: true

RSpec.configure(&:disable_monkey_patching!)

# rubocop: disable Style/MixinUsage
require 'tls13'
include TLS13
include TLS13::Message
include TLS13::Message::Extension
include TLS13::Cryptograph
# rubocop: enable Style/MixinUsage

TESTBINARY_RECORD_HEADER = <<BIN.split.map(&:hex).map(&:chr).join
  16 03 03 00 00
BIN
TESTBINARY_CIPHER_SUITES = <<BIN.split.map(&:hex).map(&:chr).join
  13 02 13 03 13 01
BIN
TESTBINARY_SERVER_NAME = <<BIN.split.map(&:hex).map(&:chr).join
  00 0d 00 00 0a 67 69 74     68 75 62 2e 63 6f 6d
BIN
TESTBINARY_STATUS_REQUEST = <<BIN.split.map(&:hex).map(&:chr).join
  01 00 00 00 00
BIN
TESTBINARY_SUPPORTED_GROUPS = <<BIN.split.map(&:hex).map(&:chr).join
  00 08 00 17 00 18 00 19    00 1d
BIN
TESTBINARY_SUPPORTED_VERSIONS = <<BIN.split.map(&:hex).map(&:chr).join
  02 03 04
BIN
TESTBINARY_KEY_SHARE = <<BIN.split.map(&:hex).map(&:chr).join
  00 24 00 1d 00 20 99 38     1d e5 60 e4 bd 43 d2 3d
  8e 43 5a 7d ba fe b3 c0     6e 51 c1 3c ae 4d 54 13
  69 1e 52 9a af 2c
BIN
TESTBINARY_SIGNATURE_ALGORITHMS = <<BIN.split.map(&:hex).map(&:chr).join
  00 12 04 03 08 04 04 01     05 03 08 05 05 01 08 06
  06 01 02 01
BIN
TESTBINARY_SIGNATURE_ALGORITHMS_CERT = TESTBINARY_SIGNATURE_ALGORITHMS
TESTBINARY_COOKIE = <<BIN.split.map(&:hex).map(&:chr).join
  00 20 6a d9 1d 2c d6 cc     f1 3b 3d 48 cc 5d cb bd
  84 77 6b c3 f4 f0 9f 8d     53 dc 11 7a dd c0 9c 40
  8d 4a
BIN
TESTBINARY_PSK_KEY_EXCHANGE_MODES = <<BIN.split.map(&:hex).map(&:chr).join
  02 00 01
BIN
TESTBINARY_RECORD_SIZE_LIMIT = <<BIN.split.map(&:hex).map(&:chr).join
  40 00
BIN
TESTBINARY_PRE_SHARED_KEY = <<BIN.split.map(&:hex).map(&:chr).join
  00 26 00 20 b2 83 3b 1e     5c 0e 9f ae b2 ef 16 37
  11 0f bd 3d 58 18 cc 06     a1 d4 8c 59 45 19 1e b5
  f7 3f 07 60 1f 5c c4 77     00 21 20 99 9e 2b 8b d7
  e0 01 12 f0 ab 0e 26 c5     6a 59 85 b4 40 53 9e b8
  e9 18 b6 7e c0 02 c3 bc     07 dd 09
BIN

# https://tools.ietf.org/html/rfc8448#page-3

TESTBINARY_CLIENT_HELLO = <<BIN.split.map(&:hex).map(&:chr).join
  01 00 00 c0 03 03 cb 34     ec b1 e7 81 63 ba 1c 38
  c6 da cb 19 6a 6d ff a2     1a 8d 99 12 ec 18 a2 ef
  62 83 02 4d ec e7 00 00     06 13 01 13 03 13 02 01
  00 00 91 00 00 00 0b 00     09 00 00 06 73 65 72 76
  65 72 ff 01 00 01 00 00     0a 00 14 00 12 00 1d 00
  17 00 18 00 19 01 00 01     01 01 02 01 03 01 04 00
  23 00 00 00 33 00 26 00     24 00 1d 00 20 99 38 1d
  e5 60 e4 bd 43 d2 3d 8e     43 5a 7d ba fe b3 c0 6e
  51 c1 3c ae 4d 54 13 69     1e 52 9a af 2c 00 2b 00
  03 02 03 04 00 0d 00 20     00 1e 04 03 05 03 06 03
  02 03 08 04 08 05 08 06     04 01 05 01 06 01 02 01
  04 02 05 02 06 02 02 02     00 2d 00 02 01 01 00 1c
  00 02 40 01
BIN
