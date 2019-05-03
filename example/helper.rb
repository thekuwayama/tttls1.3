# frozen_string_literal: true

$LOAD_PATH << __dir__ + '/../lib'

require 'socket'
require 'tttls1.3'

def http_get(hostname)
  <<~BIN
    GET / HTTP/1.1\r
    Host: #{hostname}\r
    User-Agent: https_client\r
    Accept: */*\r
    \r
  BIN
end
