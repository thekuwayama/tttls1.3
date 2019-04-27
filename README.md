# tttls1.3

[![Build Status](https://travis-ci.org/thekuwayama/tttls1.3.svg?branch=master)](https://travis-ci.org/thekuwayama/tttls1.3) [![Maintainability](https://api.codeclimate.com/v1/badges/47f3c267d9cfd2c8e388/maintainability)](https://codeclimate.com/github/thekuwayama/tttls1.3/maintainability)

tttls1.3 is Ruby implementation of [TLS 1.3](https://tools.ietf.org/html/rfc8446) protocol.
tttls1.3 uses [openssl](https://github.com/ruby/openssl) as backend for crypto and X.509 operations.

It is the purpose of this project to understand the TLS 1.3 protocol and implement the TLS 1.3 protocol using Ruby.
Backward compatibility and performance are not an objective.
This gem should not be used for production software.


## Features

tttls1.3 provides client API with the following features:

* Simple 1-RTT Handshake
* HelloRetryRequest
* Resumed 0-RTT Handshake (with PSK from ticket)

NOT supports X25519, X448, FFDHE, AES-CCM, Client Authentication, Post-Handshake Authentication, KeyUpdate, external PSKs.


## Getting started

tttls1.3 gem is available at [rubygems.org](https://rubygems.org/gems/tttls1.3). You can install with:

```
$ gem install tttls1.3
```

This implementation provides only minimal API, so your code is responsible for application layer.
Roughly, this works as follows:

```
require 'tttls1.3'

socket = YourTransport.new
client = TTTLS13::Client.new(socket, YOUR_HOSTNAME)
client.connect

client.write(YOUR_MESSAGE)
client.read
client.close
```

HTTPS examples are [here](https://github.com/thekuwayama/tttls1.3/tree/master/example).


## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
