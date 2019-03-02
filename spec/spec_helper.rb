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

TESTBINARY_RECORD_CCS = <<BIN.split.map(&:hex).map(&:chr).join
  14 03 03 00 01 01
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

TESTBINARY_CHANGE_CIPHER_SPEC = <<BIN.split.map(&:hex).map(&:chr).join
  01
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

# certificate signed by private CA for test
# rubocop: disable Layout/IndentHeredoc
TESTCERTIFICATE = <<PEM
-----BEGIN CERTIFICATE-----
MIIEnzCCAoegAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwEjEQMA4GA1UEAwwHdGVz
dC1jYTAeFw0xOTAzMDIyMjUzMzBaFw0yMDAzMDEyMjUzMzBaMBYxFDASBgNVBAMM
C3Rlc3Qtc2VydmVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1UYu
vRqOIh4Fz51P8fnJA2bvgxCLXl1DdRVArYgezACEU1/L0Bg/SpepkVnro3xMIzl0
XLOr89BJo2yLL24cyXv+0JSWph/9e+cyNei+PxLkubNYdWX7Q1UFWCRH8oNdtHkd
8Nbpg2oNl0AQmJNGLc2jnVGj7TgggQX3/zeCwMgOUOgkZRdDJhYevjSMq0Z6BUm2
xMgsgO83PlM14wK6A4XMzKmp3W/XYiVDTp/2kv99gsl26xE0CjtcI9y9Th3Kl3FM
6frub6Gxs8RVSGVtKjiK3/Q6KlUjeU0qPrxJmL3rYZ8LcMboJ5FQ3XAbJZLMGxBJ
hqX4rRt6tA/8MJtNIwIDAQABo4H6MIH3MAkGA1UdEwQCMAAwEQYJYIZIAYb4QgEB
BAQDAgZAMDMGCWCGSAGG+EIBDQQmFiRPcGVuU1NMIEdlbmVyYXRlZCBTZXJ2ZXIg
Q2VydGlmaWNhdGUwHQYDVR0OBBYEFLHdvhnSFz5ZinYHgZGHpvqW18mmMEIGA1Ud
IwQ7MDmAFNADTOOA4WhCx7T5GZSu9jRZ3Jf+oRakFDASMRAwDgYDVQQDDAd0ZXN0
LWNhggkAulRQOkaqJnYwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUF
BwMBMBoGA1UdEQQTMBGCCWxvY2FsaG9zdIcEfwAAATANBgkqhkiG9w0BAQsFAAOC
AgEAFAN52tvtW2x0zmUqElXMEE70KEP8gXjKFqefMkUjnJ7YywX/UKmTckMjOgci
d4X/d/iPDTPG0SlGJV3krH3hv+UJjw/rKXrRF3kRgFGZAWd3WHPtQlwbkWk5c0f/
uALWXScsMJ2loTVvtXFQGajIw/vfIvTm4/zWcF/Mvdap9iDQua0dU+CqVmPT1OGI
HQV3/WP8i6MsngGbp6nkjCVEyJOY425ol8PxA55A7qlHwvu/56YenjnOq1FkWu58
CL2tijnFaoHk1olxwJF+z9C7xqaWnbn7CgGUcFx+gG9+0Lk4IDmOZNeGSZnxuVaJ
vVNG5uOn/zQyADOZxYDGxe5E6SEA/IiqkbdfjV/GPi5qWy6ts/YfKaYxr5fKlFfs
vU9n145z+meLFaptBbA8jy8CsIKZCMiU3GGMzf+wxuZpqlwTzPiqH0bVSLQRv3cM
Smign0Qj+7yaGkSP7IBdguYfRezhGFnFu2QuUFY+SDH4ERC9xVyAmAKHMMKbosfY
W7zS8azT8NwG+sweIqReR7nOYiTSgY4akoQX9VQVjr2FhIdZl9QitRYoSaclcUyA
DjeUXnBSA1h3RnE6B7wfPc0ntaFz5BEwr68boTf8KsAXmfdwTnhHZ6l/geaxkb6+
c5jeKkmgc6sH8AWcqeZJJMXT9r+94nIWdwrO9NSUf3nqw/g=
-----END CERTIFICATE-----
PEM
# rubocop: enable Layout/IndentHeredoc
