# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'helper'
require 'etc'
require 'logger'

port = ARGV[0] || 4433

tcpserver = TCPServer.open(port)
settings = {
  crt_file: __dir__ + '/../tmp/server.crt',
  key_file: __dir__ + '/../tmp/server.key',
  alpn: ['http/1.1']
}

q = Queue.new
logger = Logger.new(STDERR, Logger::WARN)
# rubocop: disable Metrics/BlockLength
Etc.nprocessors.times do
  Thread.start do
    loop do
      s = q.pop
      Timeout.timeout(1) do
        server = TTTLS13::Server.new(s, settings)
        parser = HTTP::Parser.new

        parser.on_message_complete = proc do
          if !parser.http_method.nil?
            logger.info 'Receive Request'
            server.write(simple_http_response('TEST'))
            server.close
          else
            logger.warn 'Not Request'
          end
        end

        begin
          server.accept
          parser << server.read until server.eof?
        rescue HTTP::Parser::Error, TTTLS13::Error::ErrorAlerts
          logger.warn 'Parser Error'
        ensure
          server.close unless server.eof?
          parser.reset!
        end
      end
    rescue Timeout::Error
      logger.warn 'Timeout'
    ensure
      s.close
    end
  end
end
# rubocop: enable Metrics/BlockLength

loop do
  socket = tcpserver.accept
  q << socket
end
