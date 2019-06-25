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

loop do
  socket = tcpserver.accept
  Thread.start(socket) do |s|
    Timeout.timeout(5) do
      server = TTTLS13::Server.new(s, settings)
      server.accept

      parser = HTTP::Parser.new
      parser.on_message_complete = proc do
        server.write(simple_http_response('TEST'))
      end
      parser << server.read unless server.eof?
      server.close
    end
  rescue Timeout::Error => e
    puts e.to_s + "\n\n"
  ensure
    s.close
  end
end
