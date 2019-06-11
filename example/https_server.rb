# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'helper'

port = ARGV[0] || 4433

tcpserver = TCPServer.open(port)
settings = {
  crt_file: __dir__ + '/../tmp/server.crt',
  key_file: __dir__ + '/../tmp/server.key',
  alpn: ['http/1.1', 'http/1.0']
}

# rubocop: disable Metrics/BlockLength
loop do
  socket = tcpserver.accept
  Thread.start(socket) do |s|
    Timeout.timeout(5) do
      server = TTTLS13::Server.new(s, settings)
      server.accept
      buffer = ''
      buffer += server.read until buffer.include?(WEBrick::CRLF * 2)
      req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
      req.parse(StringIO.new(buffer))
      puts req.to_s
      res = WEBrick::HTTPResponse.new(WEBrick::Config::HTTP)
      res.status = 200
      res.body = 'Hello'
      res.content_length = 5
      res.content_type = 'text/html'
      server.write(
        res.status_line \
        + res.header.map { |k, v| k + ': ' + v }.join(WEBrick::CRLF) \
        + WEBrick::CRLF * 2 \
        + res.body
      )
      server.close
    end
  rescue Timeout::Error => e
    puts e.to_s + "\n\n"
  ensure
    s.close
  end
end
# rubocop: enable Metrics/BlockLength
