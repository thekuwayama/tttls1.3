# encoding: ascii-8bit
# frozen_string_literal: true

RSpec.configure(&:disable_monkey_patching!)

# rubocop: disable Style/MixinUsage
require 'tls13'
include TLS13
include TLS13::CipherSuite
include TLS13::Message
include TLS13::Message::Extension
include TLS13::Cryptograph
# rubocop: enable Style/MixinUsage

class SimpleStream
  def initialize(binary = '')
    @buffer = binary
  end

  def write(binary)
    @buffer += binary
  end

  def read
    res = @buffer
    @buffer = ''
    res
  end
end

# TLS13::CipherSuites
TESTBINARY_CIPHER_SUITES = <<BIN.split.map(&:hex).map(&:chr).join
  13 02 13 03 13 01
BIN

# TLS13::Message::Extension::$Class
TESTBINARY_SERVER_NAME = <<BIN.split.map(&:hex).map(&:chr).join
  00 0d 00 00 0a 67 69 74     68 75 62 2e 63 6f 6d
BIN

TESTBINARY_STATUS_REQUEST = <<BIN.split.map(&:hex).map(&:chr).join
  01 00 00 00 00
BIN

TESTBINARY_SUPPORTED_GROUPS = <<BIN.split.map(&:hex).map(&:chr).join
  00 08 00 17 00 18 00 19     00 1d
BIN

TESTBINARY_SUPPORTED_VERSIONS_CH = <<BIN.split.map(&:hex).map(&:chr).join
  04 03 04 03 03
BIN

TESTBINARY_SUPPORTED_VERSIONS_SH = <<BIN.split.map(&:hex).map(&:chr).join
  03 04
BIN

TESTBINARY_KEY_SHARE_CH = <<BIN.split.map(&:hex).map(&:chr).join
  00 24 00 1d 00 20 99 38     1d e5 60 e4 bd 43 d2 3d
  8e 43 5a 7d ba fe b3 c0     6e 51 c1 3c ae 4d 54 13
  69 1e 52 9a af 2c
BIN

TESTBINARY_KEY_SHARE_SH = <<BIN.split.map(&:hex).map(&:chr).join
  00 1d 00 20 99 38 1d e5     60 e4 bd 43 d2 3d 8e 43
  5a 7d ba fe b3 c0 6e 51     c1 3c ae 4d 54 13 69 1e
  52 9a af 2c
BIN

TESTBINARY_KEY_SHARE_HRR = <<BIN.split.map(&:hex).map(&:chr).join
  00 1d
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

# https://tools.ietf.org/html/rfc8448#section-2
# 2.  Private Keys

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

TESTBINARY_CLIENT_FINISHED = <<BIN.split.map(&:hex).map(&:chr).join
  14 00 00 20 a8 ec 43 6d     67 76 34 ae 52 5a c1 fc
  eb e1 1a 03 9e c1 76 94     fa c6 e9 85 27 b6 42 f2
  ed d5 ce 61
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

TESTBINARY_SERVER_PARAMETERS_WRITE_KEY = <<BIN.split.map(&:hex).map(&:chr).join
  3f ce 51 60 09 c2 17 27     d0 f2 e4 e8 6e e4 03 bc
BIN

TESTBINARY_SERVER_PARAMETERS_IV = <<BIN.split.map(&:hex).map(&:chr).join
  5d 31 3e b2 67 12 76 ee     13 00 0b 30
BIN

TESTBINARY_CLIENT_FINISHED_RECORD = <<BIN.split.map(&:hex).map(&:chr).join
  17 03 03 00 35 75 ec 4d     c2 38 cc e6 0b 29 80 44
  a7 1e 21 9c 56 cc 77 b0     51 7f e9 b9 3c 7a 4b fc
  44 d8 7f 38 f8 03 38 ac     98 fc 46 de b3 84 bd 1c
  ae ac ab 68 67 d7 26 c4     05 46
BIN

TESTBINARY_CLIENT_FINISHED_WRITE_KEY = <<BIN.split.map(&:hex).map(&:chr).join
  db fa a6 93 d1 76 2c 5b     66 6a f5 d9 50 25 8d 01
BIN

TESTBINARY_CLIENT_FINISHED_IV = <<BIN.split.map(&:hex).map(&:chr).join
  5b d3 c7 1b 83 6e 0b 76     bb 73 26 5f
BIN

TESTBINARY_CLIENT_FINISHED_KEY = <<BIN.split.map(&:hex).map(&:chr).join
  b8 0a d0 10 15 fb 2f 0b     d6 5f f7 d4 da 5d 6b f8
  3f 84 82 1d 1f 87 fd c7     d3 c7 5b 5a 7b 42 d9 c4
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

# https://tools.ietf.org/html/rfc8448#section-7
# 7.  Compatibility Mode
TESTBINARY_RECORD_CCS = <<BIN.split.map(&:hex).map(&:chr).join
  14 03 03 00 01 01
BIN

TESTBINARY_CHANGE_CIPHER_SPEC = <<BIN.split.map(&:hex).map(&:chr).join
  01
BIN
