# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'helper'
require 'etc'
require 'logger'
require 'timeout'

port = ARGV[0] || 4433

settings = {
  crt_file: __dir__ + '/../tmp/server.crt',
  chain_files: [__dir__ + '/../tmp/intermediate.crt'],
  key_file: __dir__ + '/../tmp/server.key',
  alpn: ['http/1.1'],
  sslkeylogfile: '/tmp/sslkeylogfile.log'
}

q = Queue.new
logger = Logger.new($stderr, Logger::WARN)
# rubocop: disable Metrics/BlockLength
Etc.nprocessors.times do
  Thread.start do
    loop do
      s = q.pop
      Timeout.timeout(1) do
        server = TTTLS13::Server.new(s, **settings)
        parser = HTTP::Parser.new

        parser.on_message_complete = lambda do
          if !parser.http_method.nil?
            logger.info 'Receive Request'
            html = <<HTML
  <!DOCTYPE html>
  <html>
    <head>
      <meta charset="UTF-8" />
      <title>tttls1.3 test server</title>
    </head>
    <body>
  %s
    </body>
  </html>
HTML
            html = format(html, transcript_htmlize(server.transcript))
            server.write(simple_http_response(html))
            server.close
          else
            logger.warn 'Not Request'
          end
        end

        begin
          server.accept
          parser << server.read until server.eof?
          server.close
        rescue StandardError => e
          logger.warn e
        ensure
          parser.reset!
        end
      end
    rescue Timeout::Error
      logger.warn 'Timeout'
    ensure
      s&.close
    end
  end
end
# rubocop: enable Metrics/BlockLength

Socket.tcp_server_loop(port) do |socket, _addr|
  q << socket
end
