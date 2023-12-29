# frozen_string_literal: true

$LOAD_PATH << __dir__ + '/../lib'

require 'socket'
require 'time'
require 'uri'
require 'webrick'

require 'http/parser'
require 'svcb_rr_patch'

require 'tttls1.3'

def simple_http_request(hostname, path = '/')
  s = <<~REQUEST
    GET #{path} HTTP/1.1
    Host: #{hostname}
    User-Agent: tttls1.3/examples
    Accept: */*

  REQUEST

  s.gsub(WEBrick::LF, WEBrick::CRLF)
end

def simple_http_response(body)
  h = <<~RESPONSE_HEADER_EOS
    HTTP/1.1 200 OK
    Date: #{Time.now.httpdate}
    Content-Type: text/html
    Content-Length: #{body.length}
    Server: tttls1.3/examples
  RESPONSE_HEADER_EOS

  h.gsub(WEBrick::LF, WEBrick::CRLF) + WEBrick::CRLF + body
end

def recv_http_response(client)
  parser = HTTP::Parser.new
  buf = nil

  parser.on_headers_complete = lambda do |headers|
    buf =
      [
        'HTTP/' + parser.http_version.join('.'),
        parser.status_code,
        WEBrick::HTTPStatus.reason_phrase(parser.status_code)
      ].join(' ') + "\r\n" \
      + headers.map { |k, v| k + ': ' + v + WEBrick::CRLF }.join \
      + WEBrick::CRLF
  end

  parser.on_body = lambda do |chunk|
    buf += chunk
  end

  parser.on_message_complete = lambda do
    client.close
  end

  parser << client.read until client.eof?
  buf
end
