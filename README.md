# tttls1.3

[![Gem Version](https://badge.fury.io/rb/tttls1.3.svg)](https://badge.fury.io/rb/tttls1.3)
[![Actions Status](https://github.com/thekuwayama/tttls1.3/workflows/CI/badge.svg)](https://github.com/thekuwayama/tttls1.3/actions?workflow=CI)
[![Maintainability](https://api.codeclimate.com/v1/badges/b5ae1b3a43828142d2fa/maintainability)](https://codeclimate.com/github/thekuwayama/tttls1.3/maintainability)

tttls1.3 is Ruby implementation of [TLS 1.3](https://tools.ietf.org/html/rfc8446) protocol.

tttls1.3 uses [openssl](https://github.com/ruby/openssl) for crypto and X.509 operations.

It is the purpose of this project to understand the TLS 1.3 protocol and implement the TLS 1.3 protocol using Ruby.
Backward compatibility and performance are not objective.
This gem should not be used for production software.


## Features

### Client

tttls1.3 provides client API with the following features:

* Simple 1-RTT Handshake
* HelloRetryRequest
* Resumed 0-RTT Handshake (with PSK from NST)

**NOT supports** certificate with OID RSASSA-PSS, X25519, X448, FFDHE, AES-CCM, Client Authentication, Post-Handshake Authentication, KeyUpdate and external PSKs.

### Server

tttls1.3 provides server API with the following features:

* Simple 1-RTT Handshake
* HelloRetryRequest

**NOT supports** certificate with OID RSASSA-PSS, X25519, X448, FFDHE, AES-CCM, Client Authentication, Post-Handshake Authentication, KeyUpdate, external PSKs and Resumed 0-RTT Handshake.


## Getting started

tttls1.3 gem is available at [rubygems.org](https://rubygems.org/gems/tttls1.3). You can install with:

```bash
$ gem install tttls1.3
```

This implementation provides only minimal API, so your code is responsible for the application layer.
Roughly, this works as follows:

```ruby
require 'tttls1.3'

socket = YourTransport.new
client = TTTLS13::Client.new(socket, YOUR_HOSTNAME)
client.connect

client.write(YOUR_MESSAGE)
client.read
client.close
```

```ruby
require 'tttls1.3'

socket = YourTransport.new
server = TTTLS13::Server.new(
  socket.accept,
  crt_file: '/path/to/crt/file',
  key_file: '/path/to/key/file'
)
server.accept

server.read
server.write(YOUR_MESSAGE)
server.close
```

[Here](https://github.com/thekuwayama/tttls1.3/tree/main/example) are some examples of HTTPS.


## Settings

### Client

tttls1.3 client is configurable using keyword arguments.

| key | type | default value | description |
|-----|------|---------------|-------------|
| `:ca_file` | String | nil | Path to the additional root CA certificate files. If not needed to add, set nil. |
| `:cipher_suites` | Array of TTTLS13::CipherSuite constant | `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_128_GCM_SHA256` | List of cipher suites offered in ClientHello. |
| `:signature_algorithms` | Array of TTTLS13::SignatureScheme constant | `ECDSA_SECP256R1_SHA256`, `ECDSA_SECP384R1_SHA384`, `ECDSA_SECP521R1_SHA512`, `RSA_PSS_RSAE_SHA256`, `RSA_PSS_RSAE_SHA384`, `RSA_PSS_RSAE_SHA512`, `RSA_PKCS1_SHA256`, `RSA_PKCS1_SHA384`, `RSA_PKCS1_SHA512` | List of signature algorithms offered in ClientHello extensions. |
| `:signature_algorithms_cert` | Array of TTTLS13::SignatureScheme constant | nil | List of certificate signature algorithms offered in ClientHello extensions. You can set this to signal the difference between the signature algorithm and `:signature_algorithms`. |
| `:supported_groups` | Array of TTTLS13::NamedGroup constant | `SECP256R1`, `SECP384R1`, `SECP521R1` | List of named groups offered in ClientHello extensions. |
| `:key_share_groups` | Array of TTTLS13::NamedGroup constant | nil | List of named groups offered in KeyShareClientHello. In default, KeyShareClientHello has only a KeyShareEntry of most preferred named group in `:supported_groups`. You can set this to send KeyShareClientHello that has multiple KeyShareEntry. |
| `:alpn` | Array of String | nil | List of application protocols offered in ClientHello extensions. If not needed to be present, set nil. |
| `:process_new_session_ticket` | Proc | nil | Proc that processes received NewSessionTicket. Its 3 arguments are TTTLS13::Message::NewSessionTicket, resumption master secret and cipher suite. If not needed to process NewSessionTicket, set nil. |
| `:ticket` | String | nil | The ticket for PSK. |
| `:resumption_master_secret` | String | nil | The resumption master secret. |
| `:psk_cipher_suite` | TTTLS13::CipherSuite constant | nil | The cipher suite for PSK. |
| `:ticket_nonce` | String | nil | The ticket\_nonce for PSK. |
| `:ticket_age_add` | String | nil | The ticket\_age\_add for PSK. |
| `:ticket_timestamp` | Integer | nil | The ticket\_timestamp for PSK. |
| `:record_size_limit` | Integer | nil | The record\_size\_limit offerd in ClientHello extensions. If not needed to be present, set nil. |
| `:check_certificate_status` | Boolean | false | If needed to check certificate status, set true. |
| `:process_certificate_status` | Proc | `TTTLS13::Client.method(:softfail_check_certificate_status)` | Proc(or Method) that checks received OCSPResponse. Its 3 arguments are OpenSSL::OCSP::Response, end-entity certificate(OpenSSL::X509::Certificate) and certificates chain(Array of Certificate) used for verification and it returns Boolean. |
| `:compress_certificate_algorithms` | Array of TTTLS13::Message::Extension::CertificateCompressionAlgorithm constant | `ZLIB` | The compression algorithms are supported for compressing the Certificate message. |
| `:compatibility_mode` | Boolean | true | If needed to send ChangeCipherSpec, set true. |
| `:loglevel` | Logger constant | Logger::WARN | If needed to print verbose, set Logger::DEBUG. |


### Server

tttls1.3 server is configurable using keyword arguments.

| key | type | default value | description |
|-----|------|---------------|-------------|
| `:crt_file` | String | nil | Path to the certificate file. This is a required setting. |
| `:chain_files` | Array of String | nil | Paths to the itermediate certificate files. |
| `:key_file` | String | nil | Path to the private key file. This is a required setting. |
| `:cipher_suites` | Array of TTTLS13::CipherSuite constant | `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_128_GCM_SHA256` | List of supported cipher suites. |
| `:signature_algorithms` | Array of TTTLS13::SignatureScheme constant | `ECDSA_SECP256R1_SHA256`, `ECDSA_SECP384R1_SHA384`, `ECDSA_SECP521R1_SHA512`, `RSA_PSS_RSAE_SHA256`, `RSA_PSS_RSAE_SHA384`, `RSA_PSS_RSAE_SHA512`, `RSA_PKCS1_SHA256`, `RSA_PKCS1_SHA384`, `RSA_PKCS1_SHA512` | List of supported signature algorithms. |
| `:supported_groups` | Array of TTTLS13::NamedGroup constant | `SECP256R1`, `SECP384R1`, `SECP521R1` | List of supported named groups. |
| `:alpn` | Array of String | nil | List of supported application protocols. If not needed to check this extension, set nil. |
| `:process_ocsp_response` | Proc | nil | Proc that gets OpenSSL::OCSP::Response. If not needed to staple OCSP::Response, set nil. |
| `:compress_certificate_algorithms` | Array of TTTLS13::Message::Extension::CertificateCompressionAlgorithm constant | `ZLIB` | The compression algorithms are supported for compressing the Certificate message. |
| `:compatibility_mode` | Boolean | true | If needed to send ChangeCipherSpec, set true. |
| `:loglevel` | Logger constant | Logger::WARN | If needed to print verbose, set Logger::DEBUG. |


## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
