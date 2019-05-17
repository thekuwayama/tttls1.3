# frozen_string_literal: true

$LOAD_PATH << __dir__ + '/../lib'

require 'socket'
require 'tttls1.3'
require 'webrick'

def simple_http_request(hostname)
  s = <<~BIN
    GET / HTTP/1.1
    Host: #{hostname}
    User-Agent: https_client
    Accept: */*

  BIN
  s.gsub("\n", "\r\n")
end

def recv_http_response(client)
  # status line, header
  buf = ''
  buf += client.read until buf.include?(WEBrick::CRLF * 2)
  header = buf.split(WEBrick::CRLF * 2).first
  # header; Content-Length
  cl_line = header.split(WEBrick::CRLF).find { |s| s.match(/Content-Length:/i) }

  # body
  unless cl_line.nil?
    cl = cl_line.split(':').last.to_i
    buf = buf.split(WEBrick::CRLF * 2)[1..].join
    while buf.length < cl
      s = client.read
      buf += s
    end
  end

  header + WEBrick::CRLF * 2 + buf
end
