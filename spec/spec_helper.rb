# encoding: ascii-8bit
# frozen_string_literal: true

RSpec.configure(&:disable_monkey_patching!)

# rubocop: disable Style/MixinUsage
require 'openssl'
require 'tls13'
include TLS13
include TLS13::Error
include TLS13::CipherSuite
include TLS13::SignatureScheme
include TLS13::Cryptograph
include TLS13::Message
include TLS13::Message::Extension
# rubocop: enable Style/MixinUsage

class SimpleStream
  def initialize(binary = '')
    @buffer = binary
  end

  def write(binary)
    @buffer += binary
  end

  def read(len = @buffer.length)
    res = @buffer.slice(0, len)
    @buffer = @buffer[len..]
    res
  end
end

# TLS13::CipherSuites
TESTBINARY_CIPHER_SUITES = <<BIN.split.map(&:hex).map(&:chr).join
  13 02 13 03 13 01
BIN

# TLS13::Message::Extension::$Object
TESTBINARY_SERVER_NAME = <<BIN.split.map(&:hex).map(&:chr).join
  00 0d 00 00 0a 67 69 74     68 75 62 2e 63 6f 6d
BIN

TESTBINARY_STATUS_REQUEST = <<BIN.split.map(&:hex).map(&:chr).join
  01 00 00 00 00
BIN

TESTBINARY_SUPPORTED_GROUPS = <<BIN.split.map(&:hex).map(&:chr).join
  00 06 00 17 00 18 00 19
BIN

TESTBINARY_SUPPORTED_VERSIONS_CH = <<BIN.split.map(&:hex).map(&:chr).join
  04 03 04 03 03
BIN

TESTBINARY_SUPPORTED_VERSIONS_SH = <<BIN.split.map(&:hex).map(&:chr).join
  03 04
BIN

TESTBINARY_KEY_SHARE_CH = <<BIN.split.map(&:hex).map(&:chr).join
  00 45 00 17 00 41 00 01     02 03 04 05 06 07 08 09
  0a 0b 0c 0d 0e 0f 10 11     12 13 14 15 16 17 18 19
  1a 1b 1c 1d 1e 1f 20 21     22 23 24 25 26 27 28 29
  2a 2b 2c 2d 2e 2f 30 31     32 33 34 35 36 37 38 39
  3a 3b 3c 3d 3e 3f 40
BIN

TESTBINARY_KEY_SHARE_SH = <<BIN.split.map(&:hex).map(&:chr).join
  00 17 00 41 00 01 02 03     04 05 06 07 08 09 0a 0b
  0c 0d 0e 0f 10 11 12 13     14 15 16 17 18 19 1a 1b
  1c 1d 1e 1f 20 21 22 23     24 25 26 27 28 29 2a 2b
  2c 2d 2e 2f 30 31 32 33     34 35 36 37 38 39 3a 3b
  3c 3d 3e 3f 40
BIN

TESTBINARY_KEY_SHARE_HRR = <<BIN.split.map(&:hex).map(&:chr).join
  00 17
BIN

TESTBINARY_SIGNATURE_ALGORITHMS = <<BIN.split.map(&:hex).map(&:chr).join
  00 10 04 03 08 04 04 01     05 03 08 05 05 01 08 06
  06 01
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

TESTBINARY_ALPN = <<BIN.split.map(&:hex).map(&:chr).join
  00 0c 02 68 32 08 68 74      74 70 2f 31 2e 31
BIN

TESTBINARY_EARLY_DATA_INDICATION_NST = <<BIN.split.map(&:hex).map(&:chr).join
  00 00 04 00
BIN

TESTBINARY_EARLY_DATA_INDICATION_CH = ''

# https://tools.ietf.org/html/rfc8448#section-3
# 3.  Simple 1-RTT Handshake
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

TESTBINARY_EXTENSIONS = <<BIN.split.map(&:hex).map(&:chr).join
  00 91 00 00 00 0b 00 09     00 00 06 73 65 72 76 65
  72 ff 01 00 01 00 00 0a     00 14 00 12 00 1d 00 17
  00 18 00 19 01 00 01 01     01 02 01 03 01 04 00 23
  00 00 00 33 00 26 00 24     00 1d 00 20 99 38 1d e5
  60 e4 bd 43 d2 3d 8e 43     5a 7d ba fe b3 c0 6e 51
  c1 3c ae 4d 54 13 69 1e     52 9a af 2c 00 2b 00 03
  02 03 04 00 0d 00 20 00     1e 04 03 05 03 06 03 02
  03 08 04 08 05 08 06 04     01 05 01 06 01 02 01 04
  02 05 02 06 02 02 02 00     2d 00 02 01 01 00 1c 00
  02 40 01
BIN

TESTBINARY_SERVER_HELLO = <<BIN.split.map(&:hex).map(&:chr).join
  02 00 00 56 03 03 a6 af     06 a4 12 18 60 dc 5e 6e
  60 24 9c d3 4c 95 93 0c     8a c5 cb 14 34 da c1 55
  77 2e d3 e2 69 28 00 13     01 00 00 2e 00 33 00 24
  00 1d 00 20 c9 82 88 76     11 20 95 fe 66 76 2b db
  f7 c6 72 e1 56 d6 cc 25     3b 83 3d f1 dd 69 b1 b0
  4e 75 1f 0f 00 2b 00 02     03 04
BIN

TESTBINARY_ENCRYPTED_EXTENSIONS = <<BIN.split.map(&:hex).map(&:chr).join
  08 00 00 24 00 22 00 0a     00 14 00 12 00 1d 00 17
  00 18 00 19 01 00 01 01     01 02 01 03 01 04 00 1c
  00 02 40 01 00 00 00 00
BIN

TESTBINARY_CERTIFICATE = <<BIN.split.map(&:hex).map(&:chr).join
  0b 00 01 b9 00 00 01 b5     00 01 b0 30 82 01 ac 30
  82 01 15 a0 03 02 01 02     02 01 02 30 0d 06 09 2a
  86 48 86 f7 0d 01 01 0b     05 00 30 0e 31 0c 30 0a
  06 03 55 04 03 13 03 72     73 61 30 1e 17 0d 31 36
  30 37 33 30 30 31 32 33     35 39 5a 17 0d 32 36 30
  37 33 30 30 31 32 33 35     39 5a 30 0e 31 0c 30 0a
  06 03 55 04 03 13 03 72     73 61 30 81 9f 30 0d 06
  09 2a 86 48 86 f7 0d 01     01 01 05 00 03 81 8d 00
  30 81 89 02 81 81 00 b4     bb 49 8f 82 79 30 3d 98
  08 36 39 9b 36 c6 98 8c     0c 68 de 55 e1 bd b8 26
  d3 90 1a 24 61 ea fd 2d     e4 9a 91 d0 15 ab bc 9a
  95 13 7a ce 6c 1a f1 9e     aa 6a f9 8c 7c ed 43 12
  09 98 e1 87 a8 0e e0 cc     b0 52 4b 1b 01 8c 3e 0b
  63 26 4d 44 9a 6d 38 e2     2a 5f da 43 08 46 74 80
  30 53 0e f0 46 1c 8c a9     d9 ef bf ae 8e a6 d1 d0
  3e 2b d1 93 ef f0 ab 9a     80 02 c4 74 28 a6 d3 5a
  8d 88 d7 9f 7f 1e 3f 02     03 01 00 01 a3 1a 30 18
  30 09 06 03 55 1d 13 04     02 30 00 30 0b 06 03 55
  1d 0f 04 04 03 02 05 a0     30 0d 06 09 2a 86 48 86
  f7 0d 01 01 0b 05 00 03     81 81 00 85 aa d2 a0 e5
  b9 27 6b 90 8c 65 f7 3a     72 67 17 06 18 a5 4c 5f
  8a 7b 33 7d 2d f7 a5 94     36 54 17 f2 ea e8 f8 a5
  8c 8f 81 72 f9 31 9c f3     6b 7f d6 c5 5b 80 f2 1a
  03 01 51 56 72 60 96 fd     33 5e 5e 67 f2 db f1 02
  70 2e 60 8c ca e6 be c1     fc 63 a4 2a 99 be 5c 3e
  b7 10 7c 3c 54 e9 b9 eb     2b d5 20 3b 1c 3b 84 e0
  a8 b2 f7 59 40 9b a3 ea     c9 d9 1d 40 2d cc 0c c8
  f8 96 12 29 ac 91 87 b4     2b 4d e1 00 00
BIN

TESTBINARY_CERTIFICATE_VERIFY = <<BIN.split.map(&:hex).map(&:chr).join
  0f 00 00 84 08 04 00 80     5a 74 7c 5d 88 fa 9b d2
  e5 5a b0 85 a6 10 15 b7     21 1f 82 4c d4 84 14 5a
  b3 ff 52 f1 fd a8 47 7b     0b 7a bc 90 db 78 e2 d3
  3a 5c 14 1a 07 86 53 fa     6b ef 78 0c 5e a2 48 ee
  aa a7 85 c4 f3 94 ca b6     d3 0b be 8d 48 59 ee 51
  1f 60 29 57 b1 54 11 ac     02 76 71 45 9e 46 44 5c
  9e a5 8c 18 1e 81 8e 95     b8 c3 fb 0b f3 27 84 09
  d3 be 15 2a 3d a5 04 3e     06 3d da 65 cd f5 ae a2
  0d 53 df ac d4 2f 74 f3
BIN

TESTBINARY_SERVER_FINISHED = <<BIN.split.map(&:hex).map(&:chr).join
  14 00 00 20 9b 9b 14 1d     90 63 37 fb d2 cb dc e7
  1d f4 de da 4a b4 2c 30     95 72 cb 7f ff ee 54 54
  b7 8f 07 18
BIN

TESTBINARY_SERVER_PARAMETERS = <<BIN.split.map(&:hex).map(&:chr).join
  08 00 00 24 00 22 00 0a     00 14 00 12 00 1d 00 17
  00 18 00 19 01 00 01 01     01 02 01 03 01 04 00 1c
  00 02 40 01 00 00 00 00     0b 00 01 b9 00 00 01 b5
  00 01 b0 30 82 01 ac 30     82 01 15 a0 03 02 01 02
  02 01 02 30 0d 06 09 2a     86 48 86 f7 0d 01 01 0b
  05 00 30 0e 31 0c 30 0a     06 03 55 04 03 13 03 72
  73 61 30 1e 17 0d 31 36     30 37 33 30 30 31 32 33
  35 39 5a 17 0d 32 36 30     37 33 30 30 31 32 33 35
  39 5a 30 0e 31 0c 30 0a     06 03 55 04 03 13 03 72
  73 61 30 81 9f 30 0d 06     09 2a 86 48 86 f7 0d 01
  01 01 05 00 03 81 8d 00     30 81 89 02 81 81 00 b4
  bb 49 8f 82 79 30 3d 98     08 36 39 9b 36 c6 98 8c
  0c 68 de 55 e1 bd b8 26     d3 90 1a 24 61 ea fd 2d
  e4 9a 91 d0 15 ab bc 9a     95 13 7a ce 6c 1a f1 9e
  aa 6a f9 8c 7c ed 43 12     09 98 e1 87 a8 0e e0 cc
  b0 52 4b 1b 01 8c 3e 0b     63 26 4d 44 9a 6d 38 e2
  2a 5f da 43 08 46 74 80     30 53 0e f0 46 1c 8c a9
  d9 ef bf ae 8e a6 d1 d0     3e 2b d1 93 ef f0 ab 9a
  80 02 c4 74 28 a6 d3 5a     8d 88 d7 9f 7f 1e 3f 02
  03 01 00 01 a3 1a 30 18     30 09 06 03 55 1d 13 04
  02 30 00 30 0b 06 03 55     1d 0f 04 04 03 02 05 a0
  30 0d 06 09 2a 86 48 86     f7 0d 01 01 0b 05 00 03
  81 81 00 85 aa d2 a0 e5     b9 27 6b 90 8c 65 f7 3a
  72 67 17 06 18 a5 4c 5f     8a 7b 33 7d 2d f7 a5 94
  36 54 17 f2 ea e8 f8 a5     8c 8f 81 72 f9 31 9c f3
  6b 7f d6 c5 5b 80 f2 1a     03 01 51 56 72 60 96 fd
  33 5e 5e 67 f2 db f1 02     70 2e 60 8c ca e6 be c1
  fc 63 a4 2a 99 be 5c 3e     b7 10 7c 3c 54 e9 b9 eb
  2b d5 20 3b 1c 3b 84 e0     a8 b2 f7 59 40 9b a3 ea
  c9 d9 1d 40 2d cc 0c c8     f8 96 12 29 ac 91 87 b4
  2b 4d e1 00 00 0f 00 00     84 08 04 00 80 5a 74 7c
  5d 88 fa 9b d2 e5 5a b0     85 a6 10 15 b7 21 1f 82
  4c d4 84 14 5a b3 ff 52     f1 fd a8 47 7b 0b 7a bc
  90 db 78 e2 d3 3a 5c 14     1a 07 86 53 fa 6b ef 78
  0c 5e a2 48 ee aa a7 85     c4 f3 94 ca b6 d3 0b be
  8d 48 59 ee 51 1f 60 29     57 b1 54 11 ac 02 76 71
  45 9e 46 44 5c 9e a5 8c     18 1e 81 8e 95 b8 c3 fb
  0b f3 27 84 09 d3 be 15     2a 3d a5 04 3e 06 3d da
  65 cd f5 ae a2 0d 53 df     ac d4 2f 74 f3 14 00 00
  20 9b 9b 14 1d 90 63 37     fb d2 cb dc e7 1d f4 de
  da 4a b4 2c 30 95 72 cb     7f ff ee 54 54 b7 8f 07
  18
BIN

TESTBINARY_SERVER_PARAMETERS_RECORD = <<BIN.split.map(&:hex).map(&:chr).join
  17 03 03 02 a2 d1 ff 33     4a 56 f5 bf f6 59 4a 07
  cc 87 b5 80 23 3f 50 0f     45 e4 89 e7 f3 3a f3 5e
  df 78 69 fc f4 0a a4 0a     a2 b8 ea 73 f8 48 a7 ca
  07 61 2e f9 f9 45 cb 96     0b 40 68 90 51 23 ea 78
  b1 11 b4 29 ba 91 91 cd     05 d2 a3 89 28 0f 52 61
  34 aa dc 7f c7 8c 4b 72     9d f8 28 b5 ec f7 b1 3b
  d9 ae fb 0e 57 f2 71 58     5b 8e a9 bb 35 5c 7c 79
  02 07 16 cf b9 b1 18 3e     f3 ab 20 e3 7d 57 a6 b9
  d7 47 76 09 ae e6 e1 22     a4 cf 51 42 73 25 25 0c
  7d 0e 50 92 89 44 4c 9b     3a 64 8f 1d 71 03 5d 2e
  d6 5b 0e 3c dd 0c ba e8     bf 2d 0b 22 78 12 cb b3
  60 98 72 55 cc 74 41 10     c4 53 ba a4 fc d6 10 92
  8d 80 98 10 e4 b7 ed 1a     8f d9 91 f0 6a a6 24 82
  04 79 7e 36 a6 a7 3b 70     a2 55 9c 09 ea d6 86 94
  5b a2 46 ab 66 e5 ed d8     04 4b 4c 6d e3 fc f2 a8
  94 41 ac 66 27 2f d8 fb     33 0e f8 19 05 79 b3 68
  45 96 c9 60 bd 59 6e ea     52 0a 56 a8 d6 50 f5 63
  aa d2 74 09 96 0d ca 63     d3 e6 88 61 1e a5 e2 2f
  44 15 cf 95 38 d5 1a 20     0c 27 03 42 72 96 8a 26
  4e d6 54 0c 84 83 8d 89     f7 2c 24 46 1a ad 6d 26
  f5 9e ca ba 9a cb bb 31     7b 66 d9 02 f4 f2 92 a3
  6a c1 b6 39 c6 37 ce 34     31 17 b6 59 62 22 45 31
  7b 49 ee da 0c 62 58 f1     00 d7 d9 61 ff b1 38 64
  7e 92 ea 33 0f ae ea 6d     fa 31 c7 a8 4d c3 bd 7e
  1b 7a 6c 71 78 af 36 87     90 18 e3 f2 52 10 7f 24
  3d 24 3d c7 33 9d 56 84     c8 b0 37 8b f3 02 44 da
  8c 87 c8 43 f5 e5 6e b4     c5 e8 28 0a 2b 48 05 2c
  f9 3b 16 49 9a 66 db 7c     ca 71 e4 59 94 26 f7 d4
  61 e6 6f 99 88 2b d8 9f     c5 08 00 be cc a6 2d 6c
  74 11 6d bd 29 72 fd a1     fa 80 f8 5d f8 81 ed be
  5a 37 66 89 36 b3 35 58     3b 59 91 86 dc 5c 69 18
  a3 96 fa 48 a1 81 d6 b6     fa 4f 9d 62 d5 13 af bb
  99 2f 2b 99 2f 67 f8 af     e6 7f 76 91 3f a3 88 cb
  56 30 c8 ca 01 e0 c6 5d     11 c6 6a 1e 2a c4 c8 59
  77 b7 c7 a6 99 9b bf 10     dc 35 ae 69 f5 51 56 14
  63 6c 0b 9b 68 c1 9e d2     e3 1c 0b 3b 66 76 30 38
  eb ba 42 f3 b3 8e dc 03     99 f3 a9 f2 3f aa 63 97
  8c 31 7f c9 fa 66 a7 3f     60 f0 50 4d e9 3b 5b 84
  5e 27 55 92 c1 23 35 ee     34 0b bc 4f dd d5 02 78
  40 16 e4 b3 be 7e f0 4d     da 49 f4 b4 40 a3 0c b5
  d2 af 93 98 28 fd 4a e3     79 4e 44 f9 4d f5 a6 31
  ed e4 2c 17 19 bf da bf     02 53 fe 51 75 be 89 8e
  75 0e dc 53 37 0d 2b
BIN

TESTBINARY_CLIENT_FINISHED = <<BIN.split.map(&:hex).map(&:chr).join
  14 00 00 20 a8 ec 43 6d     67 76 34 ae 52 5a c1 fc
  eb e1 1a 03 9e c1 76 94     fa c6 e9 85 27 b6 42 f2
  ed d5 ce 61
BIN

TESTBINARY_CLIENT_FINISHED_RECORD = <<BIN.split.map(&:hex).map(&:chr).join
  17 03 03 00 35 75 ec 4d     c2 38 cc e6 0b 29 80 44
  a7 1e 21 9c 56 cc 77 b0     51 7f e9 b9 3c 7a 4b fc
  44 d8 7f 38 f8 03 38 ac     98 fc 46 de b3 84 bd 1c
  ae ac ab 68 67 d7 26 c4     05 46
BIN

TESTBINARY_NEW_SESSION_TICKET = <<BIN.split.map(&:hex).map(&:chr).join
  04 00 00 c9 00 00 00 1e     fa d6 aa c5 02 00 00 00
  b2 2c 03 5d 82 93 59 ee     5f f7 af 4e c9 00 00 00
  00 26 2a 64 94 dc 48 6d     2c 8a 34 cb 33 fa 90 bf
  1b 00 70 ad 3c 49 88 83     c9 36 7c 09 a2 be 78 5a
  bc 55 cd 22 60 97 a3 a9     82 11 72 83 f8 2a 03 a1
  43 ef d3 ff 5d d3 6d 64     e8 61 be 7f d6 1d 28 27
  db 27 9c ce 14 50 77 d4     54 a3 66 4d 4e 6d a4 d2
  9e e0 37 25 a6 a4 da fc     d0 fc 67 d2 ae a7 05 29
  51 3e 3d a2 67 7f a5 90     6c 5b 3f 7d 8f 92 f2 28
  bd a4 0d da 72 14 70 f9     fb f2 97 b5 ae a6 17 64
  6f ac 5c 03 27 2e 97 07     27 c6 21 a7 91 41 ef 5f
  7d e6 50 5e 5b fb c3 88     e9 33 43 69 40 93 93 4a
  e4 d3 57 00 08 00 2a 00     04 00 00 04 00
BIN

TESTBINARY_CLIENT_APPLICATION_DATA = <<BIN.split.map(&:hex).map(&:chr).join
  00 01 02 03 04 05 06 07     08 09 0a 0b 0c 0d 0e 0f
  10 11 12 13 14 15 16 17     18 19 1a 1b 1c 1d 1e 1f
  20 21 22 23 24 25 26 27     28 29 2a 2b 2c 2d 2e 2f
  30 31
BIN

TESTBINARY_ALERT = <<BIN.split.map(&:hex).map(&:chr).join
  01 00
BIN

TESTBINARY_SERVER_FINISHED_KEY = <<BIN.split.map(&:hex).map(&:chr).join
  00 8d 3b 66 f8 16 ea 55     9f 96 b5 37 e8 85 c3 1f
  c0 68 bf 49 2c 65 2f 01     f2 88 a1 d8 cd c1 9f c8
BIN

TESTBINARY_SERVER_PARAMETERS_WRITE_KEY = <<BIN.split.map(&:hex).map(&:chr).join
  3f ce 51 60 09 c2 17 27     d0 f2 e4 e8 6e e4 03 bc
BIN

TESTBINARY_SERVER_PARAMETERS_WRITE_IV = <<BIN.split.map(&:hex).map(&:chr).join
  5d 31 3e b2 67 12 76 ee     13 00 0b 30
BIN

TESTBINARY_CLIENT_FINISHED_KEY = <<BIN.split.map(&:hex).map(&:chr).join
  b8 0a d0 10 15 fb 2f 0b     d6 5f f7 d4 da 5d 6b f8
  3f 84 82 1d 1f 87 fd c7     d3 c7 5b 5a 7b 42 d9 c4
BIN

TESTBINARY_CLIENT_FINISHED_WRITE_KEY = <<BIN.split.map(&:hex).map(&:chr).join
  db fa a6 93 d1 76 2c 5b     66 6a f5 d9 50 25 8d 01
BIN

TESTBINARY_CLIENT_FINISHED_WRITE_IV = <<BIN.split.map(&:hex).map(&:chr).join
  5b d3 c7 1b 83 6e 0b 76     bb 73 26 5f
BIN

TESTBINARY_SERVER_APPLICATION_WRITE_KEY = <<BIN.split.map(&:hex).map(&:chr).join
  9f 02 28 3b 6c 9c 07 ef     c2 6b b9 f2 ac 92 e3 56
BIN

TESTBINARY_SERVER_APPLICATION_WRITE_IV = <<BIN.split.map(&:hex).map(&:chr).join
  cf 78 2b 88 dd 83 54 9a     ad f1 e9 84
BIN

TESTBINARY_CLIENT_APPLICATION_WRITE_KEY = <<BIN.split.map(&:hex).map(&:chr).join
  17 42 2d da 59 6e d5 d9     ac d8 90 e3 c6 3f 50 51
BIN

TESTBINARY_CLIENT_APPLICATION_WRITE_IV = <<BIN.split.map(&:hex).map(&:chr).join
  5b 78 92 3d ee 08 57 90     33 e5 23 d9
BIN

TESTBINARY_SHARED_SECRET = <<BIN.split.map(&:hex).map(&:chr).join
  8b d4 05 4f b5 5b 9d 63     fd fb ac f9 f0 4b 9f 0d
  35 e6 d6 3f 53 75 63 ef     d4 62 72 90 0f 89 49 2d
BIN

TESTBINARY_C_HS_TRAFFIC = <<BIN.split.map(&:hex).map(&:chr).join
  b3 ed db 12 6e 06 7f 35     a7 80 b3 ab f4 5e 2d 8f
  3b 1a 95 07 38 f5 2e 96     00 74 6a 0e 27 a5 5a 21
BIN

TESTBINARY_S_HS_TRAFFIC = <<BIN.split.map(&:hex).map(&:chr).join
  b6 7b 7d 69 0c c1 6c 4e     75 e5 42 13 cb 2d 37 b4
  e9 c9 12 bc de d9 10 5d     42 be fd 59 d3 91 ad 38
BIN

TESTBINARY_C_AP_TRAFFIC = <<BIN.split.map(&:hex).map(&:chr).join
  9e 40 64 6c e7 9a 7f 9d     c0 5a f8 88 9b ce 65 52
  87 5a fa 0b 06 df 00 87     f7 92 eb b7 c1 75 04 a5
BIN

TESTBINARY_S_AP_TRAFFIC = <<BIN.split.map(&:hex).map(&:chr).join
  a1 1a f9 f0 55 31 f8 56     ad 47 11 6b 45 a9 50 32
  82 04 b4 f4 4b fb 6b 3a     4b 4f 1f 3f cb 63 16 43
BIN

TESTBINARY_EXP_MASTER = <<BIN.split.map(&:hex).map(&:chr).join
  fe 22 f8 81 17 6e da 18     eb 8f 44 52 9e 67 92 c5
  0c 9a 3f 89 45 2f 68 d8     ae 31 1b 43 09 d3 cf 50
BIN

TESTBINARY_RES_MASTER = <<BIN.split.map(&:hex).map(&:chr).join
  7d f2 35 f2 03 1d 2a 05     12 87 d0 2b 02 41 b0 bf
  da f8 6c c8 56 23 1f 2d     5a ba 46 c4 34 ec 19 6c
BIN

TESTBINARY_CH_CF_TRANSCRIPT_HASH = <<BIN.split.map(&:hex).map(&:chr).join
  20 91 45 a9 6e e8 e2 a1     22 ff 81 00 47 cc 95 26
  84 65 8d 60 49 e8 64 29     42 6d b8 7c 54 ad 14 3d
BIN

# https://tools.ietf.org/html/rfc8448#section-5
# 5.  HelloRetryRequest

TESTBINARY_HRR_CLIENT_HELLO1 = <<BIN.split.map(&:hex).map(&:chr).join
  01 00 00 b0 03 03 b0 b1     c5 a5 aa 37 c5 91 9f 2e
  d1 d5 c6 ff f7 fc b7 84     97 16 94 5a 2b 8c ee 92
  58 a3 46 67 7b 6f 00 00     06 13 01 13 03 13 02 01
  00 00 81 00 00 00 0b 00     09 00 00 06 73 65 72 76
  65 72 ff 01 00 01 00 00     0a 00 08 00 06 00 1d 00
  17 00 18 00 33 00 26 00     24 00 1d 00 20 e8 e8 e3
  f3 b9 3a 25 ed 97 a1 4a     7d ca cb 8a 27 2c 62 88
  e5 85 c6 48 4d 05 26 2f     ca d0 62 ad 1f 00 2b 00
  03 02 03 04 00 0d 00 20     00 1e 04 03 05 03 06 03
  02 03 08 04 08 05 08 06     04 01 05 01 06 01 02 01
  04 02 05 02 06 02 02 02     00 2d 00 02 01 01 00 1c
  00 02 40 01
BIN

TESTBINARY_HRR_HELLO_RETRY_REQUEST = <<BIN.split.map(&:hex).map(&:chr).join
  02 00 00 ac 03 03 cf 21     ad 74 e5 9a 61 11 be 1d
  8c 02 1e 65 b8 91 c2 a2     11 16 7a bb 8c 5e 07 9e
  09 e2 c8 a8 33 9c 00 13     01 00 00 84 00 33 00 02
  00 17 00 2c 00 74 00 72     71 dc d0 4b b8 8b c3 18
  91 19 39 8a 00 00 00 00     ee fa fc 76 c1 46 b8 23
  b0 96 f8 aa ca d3 65 dd     00 30 95 3f 4e df 62 56
  36 e5 f2 1b b2 e2 3f cc     65 4b 1b 5b 40 31 8d 10
  d1 37 ab cb b8 75 74 e3     6e 8a 1f 02 5f 7d fa 5d
  6e 50 78 1b 5e da 4a a1     5b 0c 8b e7 78 25 7d 16
  aa 30 30 e9 e7 84 1d d9     e4 c0 34 22 67 e8 ca 0c
  af 57 1f b2 b7 cf f0 f9     34 b0 00 2b 00 02 03 04
BIN

TESTBINARY_HRR_CLIENT_HELLO = <<BIN.split.map(&:hex).map(&:chr).join
  01 00 01 fc 03 03 b0 b1     c5 a5 aa 37 c5 91 9f 2e
  d1 d5 c6 ff f7 fc b7 84     97 16 94 5a 2b 8c ee 92
  58 a3 46 67 7b 6f 00 00     06 13 01 13 03 13 02 01
  00 01 cd 00 00 00 0b 00     09 00 00 06 73 65 72 76
  65 72 ff 01 00 01 00 00     0a 00 08 00 06 00 1d 00
  17 00 18 00 33 00 47 00     45 00 17 00 41 04 a6 da
  73 92 ec 59 1e 17 ab fd     53 59 64 b9 98 94 d1 3b
  ef b2 21 b3 de f2 eb e3     83 0e ac 8f 01 51 81 26
  77 c4 d6 d2 23 7e 85 cf     01 d6 91 0c fb 83 95 4e
  76 ba 73 52 83 05 34 15     98 97 e8 06 57 80 00 2b
  00 03 02 03 04 00 0d 00     20 00 1e 04 03 05 03 06
  03 02 03 08 04 08 05 08     06 04 01 05 01 06 01 02
  01 04 02 05 02 06 02 02     02 00 2c 00 74 00 72 71
  dc d0 4b b8 8b c3 18 91     19 39 8a 00 00 00 00 ee
  fa fc 76 c1 46 b8 23 b0     96 f8 aa ca d3 65 dd 00
  30 95 3f 4e df 62 56 36     e5 f2 1b b2 e2 3f cc 65
  4b 1b 5b 40 31 8d 10 d1     37 ab cb b8 75 74 e3 6e
  8a 1f 02 5f 7d fa 5d 6e     50 78 1b 5e da 4a a1 5b
  0c 8b e7 78 25 7d 16 aa     30 30 e9 e7 84 1d d9 e4
  c0 34 22 67 e8 ca 0c af     57 1f b2 b7 cf f0 f9 34
  b0 00 2d 00 02 01 01 00     1c 00 02 40 01 00 15 00
  af 00 00 00 00 00 00 00     00 00 00 00 00 00 00 00
  00 00 00 00 00 00 00 00     00 00 00 00 00 00 00 00
  00 00 00 00 00 00 00 00     00 00 00 00 00 00 00 00
  00 00 00 00 00 00 00 00     00 00 00 00 00 00 00 00
  00 00 00 00 00 00 00 00     00 00 00 00 00 00 00 00
  00 00 00 00 00 00 00 00     00 00 00 00 00 00 00 00
  00 00 00 00 00 00 00 00     00 00 00 00 00 00 00 00
  00 00 00 00 00 00 00 00     00 00 00 00 00 00 00 00
  00 00 00 00 00 00 00 00     00 00 00 00 00 00 00 00
  00 00 00 00 00 00 00 00     00 00 00 00 00 00 00 00
  00 00 00 00 00 00 00 00     00 00 00 00 00 00 00 00
BIN

TESTBINARY_HRR_SERVER_HELLO = <<BIN.split.map(&:hex).map(&:chr).join
  02 00 00 77 03 03 bb 34     1d 84 7f d7 89 c4 7c 38
  71 72 dc 0c 9b f1 47 fc     ca cb 50 43 d8 6c a4 c5
  98 d3 ff 57 1b 98 00 13     01 00 00 4f 00 33 00 45
  00 17 00 41 04 58 3e 05     4b 7a 66 67 2a e0 20 ad
  9d 26 86 fc c8 5b 5a d4     1a 13 4a 0f 03 ee 72 b8
  93 05 2b d8 5b 4c 8d e6     77 6f 5b 04 ac 07 d8 35
  40 ea b3 e3 d9 c5 47 bc     65 28 c4 31 7d 29 46 86
  09 3a 6c ad 7d 00 2b 00     02 03 04
BIN

TESTBINARY_HRR_ENCRYPTED_EXTENSIONS = <<BIN.split.map(&:hex).map(&:chr).join
  08 00 00 18 00 16 00 0a     00 08 00 06 00 17 00 18
  00 1d 00 1c 00 02 40 01     00 00 00 00
BIN

TESTBINARY_HRR_CERTIFICATE = <<BIN.split.map(&:hex).map(&:chr).join
  0b 00 01 b9 00 00 01 b5     00 01 b0 30 82 01 ac 30
  82 01 15 a0 03 02 01 02     02 01 02 30 0d 06 09 2a
  86 48 86 f7 0d 01 01 0b     05 00 30 0e 31 0c 30 0a
  06 03 55 04 03 13 03 72     73 61 30 1e 17 0d 31 36
  30 37 33 30 30 31 32 33     35 39 5a 17 0d 32 36 30
  37 33 30 30 31 32 33 35     39 5a 30 0e 31 0c 30 0a
  06 03 55 04 03 13 03 72     73 61 30 81 9f 30 0d 06
  09 2a 86 48 86 f7 0d 01     01 01 05 00 03 81 8d 00
  30 81 89 02 81 81 00 b4     bb 49 8f 82 79 30 3d 98
  08 36 39 9b 36 c6 98 8c     0c 68 de 55 e1 bd b8 26
  d3 90 1a 24 61 ea fd 2d     e4 9a 91 d0 15 ab bc 9a
  95 13 7a ce 6c 1a f1 9e     aa 6a f9 8c 7c ed 43 12
  09 98 e1 87 a8 0e e0 cc     b0 52 4b 1b 01 8c 3e 0b
  63 26 4d 44 9a 6d 38 e2     2a 5f da 43 08 46 74 80
  30 53 0e f0 46 1c 8c a9     d9 ef bf ae 8e a6 d1 d0
  3e 2b d1 93 ef f0 ab 9a     80 02 c4 74 28 a6 d3 5a
  8d 88 d7 9f 7f 1e 3f 02     03 01 00 01 a3 1a 30 18
  30 09 06 03 55 1d 13 04     02 30 00 30 0b 06 03 55
  1d 0f 04 04 03 02 05 a0     30 0d 06 09 2a 86 48 86
  f7 0d 01 01 0b 05 00 03     81 81 00 85 aa d2 a0 e5
  b9 27 6b 90 8c 65 f7 3a     72 67 17 06 18 a5 4c 5f
  8a 7b 33 7d 2d f7 a5 94     36 54 17 f2 ea e8 f8 a5
  8c 8f 81 72 f9 31 9c f3     6b 7f d6 c5 5b 80 f2 1a
  03 01 51 56 72 60 96 fd     33 5e 5e 67 f2 db f1 02
  70 2e 60 8c ca e6 be c1     fc 63 a4 2a 99 be 5c 3e
  b7 10 7c 3c 54 e9 b9 eb     2b d5 20 3b 1c 3b 84 e0
  a8 b2 f7 59 40 9b a3 ea     c9 d9 1d 40 2d cc 0c c8
  f8 96 12 29 ac 91 87 b4     2b 4d e1 00 00
BIN

TESTBINARY_HRR_CERTIFICATE_VERIFY = <<BIN.split.map(&:hex).map(&:chr).join
  0f 00 00 84 08 04 00 80     33 ab 13 d4 46 27 07 23
  1b 5d ca e6 c8 19 0b 63     d1 da bc 74 f2 8c 39 53
  70 da 0b 07 e5 b8 30 66     d0 24 6a 31 ac d9 5d f4
  75 bf d7 99 a4 a7 0d 33     ad 93 d3 a3 17 a9 b2 c0
  d2 37 a5 68 5b 21 9e 77     41 12 e3 91 a2 47 60 7d
  1a ef f1 bb d0 a3 9f 38     2e e1 a5 fe 88 ae 99 ec
  59 22 8e 64 97 e4 5d 48     ce 27 5a 6d 5e f4 0d 16
  9f b6 f9 d3 3b 05 2e d3     dc dd 6b 5a 48 ba af ff
  bc b2 90 12 84 15 bd 38
BIN

TESTBINARY_HRR_SERVER_FINISHED = <<BIN.split.map(&:hex).map(&:chr).join
  14 00 00 20 88 63 e6 bf     b0 42 0a 92 7f a2 7f 34
  33 6a 70 ae 42 6e 96 8e     3e b8 84 94 5b 96 85 6d
  ba 39 76 d1
BIN

TESTBINARY_HRR_SERVER_PARAMETERS = <<BIN.split.map(&:hex).map(&:chr).join
  08 00 00 18 00 16 00 0a     00 08 00 06 00 17 00 18
  00 1d 00 1c 00 02 40 01     00 00 00 00 0b 00 01 b9
  00 00 01 b5 00 01 b0 30     82 01 ac 30 82 01 15 a0
  03 02 01 02 02 01 02 30     0d 06 09 2a 86 48 86 f7
  0d 01 01 0b 05 00 30 0e     31 0c 30 0a 06 03 55 04
  03 13 03 72 73 61 30 1e     17 0d 31 36 30 37 33 30
  30 31 32 33 35 39 5a 17     0d 32 36 30 37 33 30 30
  31 32 33 35 39 5a 30 0e     31 0c 30 0a 06 03 55 04
  03 13 03 72 73 61 30 81     9f 30 0d 06 09 2a 86 48
  86 f7 0d 01 01 01 05 00     03 81 8d 00 30 81 89 02
  81 81 00 b4 bb 49 8f 82     79 30 3d 98 08 36 39 9b
  36 c6 98 8c 0c 68 de 55     e1 bd b8 26 d3 90 1a 24
  61 ea fd 2d e4 9a 91 d0     15 ab bc 9a 95 13 7a ce
  6c 1a f1 9e aa 6a f9 8c     7c ed 43 12 09 98 e1 87
  a8 0e e0 cc b0 52 4b 1b     01 8c 3e 0b 63 26 4d 44
  9a 6d 38 e2 2a 5f da 43     08 46 74 80 30 53 0e f0
  46 1c 8c a9 d9 ef bf ae     8e a6 d1 d0 3e 2b d1 93
  ef f0 ab 9a 80 02 c4 74     28 a6 d3 5a 8d 88 d7 9f
  7f 1e 3f 02 03 01 00 01     a3 1a 30 18 30 09 06 03
  55 1d 13 04 02 30 00 30     0b 06 03 55 1d 0f 04 04
  03 02 05 a0 30 0d 06 09     2a 86 48 86 f7 0d 01 01
  0b 05 00 03 81 81 00 85     aa d2 a0 e5 b9 27 6b 90
  8c 65 f7 3a 72 67 17 06     18 a5 4c 5f 8a 7b 33 7d
  2d f7 a5 94 36 54 17 f2     ea e8 f8 a5 8c 8f 81 72
  f9 31 9c f3 6b 7f d6 c5     5b 80 f2 1a 03 01 51 56
  72 60 96 fd 33 5e 5e 67     f2 db f1 02 70 2e 60 8c
  ca e6 be c1 fc 63 a4 2a     99 be 5c 3e b7 10 7c 3c
  54 e9 b9 eb 2b d5 20 3b     1c 3b 84 e0 a8 b2 f7 59
  40 9b a3 ea c9 d9 1d 40     2d cc 0c c8 f8 96 12 29
  ac 91 87 b4 2b 4d e1 00     00 0f 00 00 84 08 04 00
  80 33 ab 13 d4 46 27 07     23 1b 5d ca e6 c8 19 0b
  63 d1 da bc 74 f2 8c 39     53 70 da 0b 07 e5 b8 30
  66 d0 24 6a 31 ac d9 5d     f4 75 bf d7 99 a4 a7 0d
  33 ad 93 d3 a3 17 a9 b2     c0 d2 37 a5 68 5b 21 9e
  77 41 12 e3 91 a2 47 60     7d 1a ef f1 bb d0 a3 9f
  38 2e e1 a5 fe 88 ae 99     ec 59 22 8e 64 97 e4 5d
  48 ce 27 5a 6d 5e f4 0d     16 9f b6 f9 d3 3b 05 2e
  d3 dc dd 6b 5a 48 ba af     ff bc b2 90 12 84 15 bd
  38 14 00 00 20 88 63 e6     bf b0 42 0a 92 7f a2 7f
  34 33 6a 70 ae 42 6e 96     8e 3e b8 84 94 5b 96 85
  6d ba 39 76 d1
BIN

TESTBINARY_HRR_SERVER_PARAMETERS_RECORD = <<BIN.split.map(&:hex).map(&:chr).join
  17 03 03 02 96 99 be e2     0b af 5b 7f c7 27 bf ab
  62 23 92 8a 38 1e 6d 0c     f9 c4 da 65 3f 9d 2a 7b
  23 f7 de 11 cc e8 42 d5     cf 75 63 17 63 45 0f fb
  8b 0c c1 d2 38 e6 58 af     7a 12 ad c8 62 43 11 4a
  b1 4a 1d a2 fa e4 26 21     ce 48 3f b6 24 2e ab fa
  ad 52 56 6b 02 b3 1d 2e     dd ed ef eb 80 e6 6a 99
  00 d5 f9 73 b4 0c 4f df     74 71 9e cf 1b 68 d7 f9
  c3 b6 ce b9 03 ca 13 dd     1b b8 f8 18 7a e3 34 17
  e1 d1 52 52 2c 58 22 a1     a0 3a d5 2c 83 8c 55 95
  3d 61 02 22 87 4c ce 8e     17 90 b2 29 a2 aa 0b 53
  c8 d3 77 ee 72 01 82 95     1d c6 18 1d c5 d9 0b d1
  f0 10 5e d1 e8 4a a5 f7     59 57 c6 66 18 97 07 9e
  5e a5 00 74 49 e3 19 7b     dc 7c 9b ee ed dd ea fd
  d8 44 af a5 c3 15 ec fe     65 e5 76 af e9 09 81 28
  80 62 0e c7 04 8b 42 d7     f5 c7 8d 76 f2 99 d6 d8
  25 34 bd d8 f5 12 fe bc     0e d3 81 4a ca 47 0c d8
  00 0d 3e 1c b9 96 2b 05     2f bb 95 0d f6 83 a5 2c
  2b a7 7e d3 71 3b 12 29     37 a6 e5 17 09 64 e2 ab
  79 69 dc d9 80 b3 db 9b     45 8d a7 60 31 24 d6 dc
  00 5e 4d 6e 04 b4 d0 c4     ba f3 27 5d b8 27 db ba
  0a 6d b0 96 72 17 1f c0     57 b3 85 1d 7e 02 68 41
  e2 97 8f bd 23 46 bb ef     dd 03 76 bb 11 08 fe 9a
  cc 92 18 9f 56 50 aa 5e     85 d8 e8 c7 b6 7a c5 10
  db a0 03 d3 d7 e1 63 50     bb 66 d4 50 13 ef d4 4c
  9b 60 7c 0d 31 8c 4c 7d     1a 1f 5c bc 57 e2 06 11
  80 4e 37 87 d7 b4 a4 b5     f0 8e d8 fd 70 bd ae ad
  e0 22 60 b1 2a b8 42 ef     69 0b 4a 3e e7 91 1e 84
  1b 37 4e cd 5e bb bc 2a     54 d0 47 b6 00 33 6d d7
  d0 c8 8b 4b c1 0e 58 ee     6c b6 56 de 72 47 fa 20
  d8 e9 1d eb 84 62 86 08     cf 80 61 5b 62 e9 6c 14
  91 c7 ac 37 55 eb 69 01     40 5d 34 74 fe 1a c7 9d
  10 6a 0c ee 56 c2 57 7f     c8 84 80 f9 6c b6 b8 c6
  81 b7 b6 8b 53 c1 46 09     39 08 f3 50 88 81 75 bd
  fb 0b 1e 31 ad 61 e3 0b     a0 ad fe 6d 22 3a a0 3c
  07 83 b5 00 1a 57 58 7c     32 8a 9a fc fc fb 97 8d
  1c d4 32 8f 7d 9d 60 53     0e 63 0b ef d9 6c 0c 81
  6e e2 0b 01 00 76 8a e2     a6 df 51 fc 68 f1 72 74
  0a 79 af 11 39 8e e3 be     12 52 49 1f a9 c6 93 47
  9e 87 7f 94 ab 7c 5f 8c     ad 48 02 03 e6 ab 7b 87
  dd 71 e8 a0 72 91 13 df     17 f5 ee e8 6c e1 08 d1
  d7 20 07 ec 1c d1 3c 85     a6 c1 49 62 1e 77 b7 d7
  8d 80 5a 30 f0 be 03 0c     31 5e 54
BIN

TESTBINARY_HRR_CLIENT_FINISHED = <<BIN.split.map(&:hex).map(&:chr).join
  14 00 00 20 23 f5 2f db     07 09 a5 5b d7 f7 9b 99
  1f 25 48 40 87 bc fd 4d     43 80 b1 23 26 a5 2a 28
  b2 e3 68 e1
BIN

TESTBINARY_HRR_SHARED_SECRET = <<BIN.split.map(&:hex).map(&:chr).join
  c1 42 ce 13 ca 11 b5 c2     23 36 52 e6 3a d3 d9 78
  44 f1 62 1f bf b9 de 69     d5 47 dc 8f ed ea be b4
BIN

TESTBINARY_HRR_SERVER_FINISHED_KEY = <<BIN.split.map(&:hex).map(&:chr).join
  e7 f8 bb 3e a4 b6 c3 0c     47 10 b3 d0 9c 33 13 65
  81 17 e7 0b 09 7e 85 03     68 e2 51 0c a5 63 1f 74
BIN

testbinary = <<BIN
  46 46 bf ac 17 12 c4 26     cd 78 d8 a2 4a 8a 6f 6b
BIN
TESTBINARY_HRR_SERVER_PARAMETERS_WRITE_KEY \
= testbinary.split.map(&:hex).map(&:chr).join

testbinary = <<BIN
  c7 d3 95 c0 8d 62 f2 97     d1 37 68 ea
BIN
TESTBINARY_HRR_SERVER_PARAMETERS_WRITE_IV \
= testbinary.split.map(&:hex).map(&:chr).join

TESTBINARY_HRR_CLIENT_FINISHED_KEY = <<BIN.split.map(&:hex).map(&:chr).join
  81 be 41 31 fb b9 b6 f4     47 14 50 84 6f 74 fd 1e
  68 c5 22 4b a7 c2 a8 67     7f 5c 53 ad 22 6f dc 13
BIN

testbinary = <<BIN
  2f 1f 91 86 63 d5 90 e7     42 11 49 a2 9d 94 b0 b6
BIN
TESTBINARY_HRR_CLIENT_FINISHED_WRITE_KEY \
= testbinary.split.map(&:hex).map(&:chr).join

TESTBINARY_HRR_CLIENT_FINISHED_WRITE_IV = <<BIN.split.map(&:hex).map(&:chr).join
  41 4d 54 85 23 5e 1a 68     87 93 bd 74
BIN

testbinary = <<BIN
  f2 7a 5d 97 bd 25 55 0c     48 23 b0 f3 e5 d2 93 88
BIN
TESTBINARY_HRR_SERVER_APPLICATION_WRITE_KEY \
= testbinary.split.map(&:hex).map(&:chr).join

testbinary = <<BIN
  0d d6 31 f7 b7 1c bb c7     97 c3 5f e7
BIN
TESTBINARY_HRR_SERVER_APPLICATION_WRITE_IV \
= testbinary.split.map(&:hex).map(&:chr).join

testbinary = <<BIN
  a7 eb 2a 05 25 eb 43 31     d5 8f cb f9 f7 ca 2e 9c
BIN
TESTBINARY_HRR_CLIENT_APPLICATION_WRITE_KEY \
= testbinary.split.map(&:hex).map(&:chr).join

testbinary = <<BIN
  86 e8 be 22 7c 1b d2 b3     e3 9c b4 44
BIN
TESTBINARY_HRR_CLIENT_APPLICATION_WRITE_IV \
= testbinary.split.map(&:hex).map(&:chr).join

TESTBINARY_HRR_CH1_SH_TRANSCRIPT_HASH = <<BIN.split.map(&:hex).map(&:chr).join
  8a a8 e8 28 ec 2f 8a 88     4f ec 95 a3 13 9d e0 1c
  15 a3 da a7 ff 5b fc 3f     4b fc c2 1b 43 8d 7b f8
BIN

TESTBINARY_HRR_CH1_CF_TRANSCRIPT_HASH = <<BIN.split.map(&:hex).map(&:chr).join
  0e 8b 34 91 58 b8 55 fd     cd 0c 11 db bc 4e 83 e4
  3c aa 6e 48 3c 6c 65 df     53 15 18 88 e5 01 65 f4
BIN

# https://tools.ietf.org/html/rfc8448#section-7
# 7.  Compatibility Mode
TESTBINARY_RECORD_CCS = <<BIN.split.map(&:hex).map(&:chr).join
  14 03 03 00 01 01
BIN

TESTBINARY_CHANGE_CIPHER_SPEC = <<BIN.split.map(&:hex).map(&:chr).join
  01
BIN
