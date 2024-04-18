# frozen_string_literal: true

$LOAD_PATH << __dir__ + '/../lib'

require 'socket'
require 'time'
require 'uri'
require 'webrick'

require 'ech_config'
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

def transcript_htmlize(transcript)
  m = {
    TTTLS13::CH1 => 'ClientHello',
    TTTLS13::HRR => 'HelloRetryRequest',
    TTTLS13::CH => 'ClientHello',
    TTTLS13::SH => 'ServerHello',
    TTTLS13::EE => 'EncryptedExtensions',
    TTTLS13::CR => 'CertificateRequest',
    TTTLS13::CT => 'Certificate',
    TTTLS13::CV => 'CertificateVerify',
    TTTLS13::SF => 'Finished',
    TTTLS13::EOED => 'EndOfEarlyData',
    TTTLS13::CCT => 'Certificate',
    TTTLS13::CCV => 'CertificateVerify',
    TTTLS13::CF => 'Finished'
  }.map { |k, v| [k, '<details><summary>' + v + '</summary>%s</details>'] }.to_h
  transcript.map do |k, v|
    format(m[k], TTTLS13::Convert.obj2html(v.first))
  end.join('<br>')
end

def parse_echconfigs_pem(pem)
  s = pem.gsub(/-----(BEGIN|END) ECH CONFIGS-----/, '')
         .gsub("\n", '')
  b = Base64.decode64(s)
  raise 'failed to parse ECHConfigs' \
    unless b.length == b.slice(0, 2).unpack1('n') + 2

  ECHConfig.decode_vectors(b.slice(2..))
end

def resolve_echconfig(hostname)
  rr = Resolv::DNS.new.getresources(
    hostname,
    Resolv::DNS::Resource::IN::HTTPS
  )
  raise "failed to resolve echconfig via #{hostname} HTTPS RR" \
    if rr.first.nil? || !rr.first.svc_params.keys.include?('ech')

  rr.first.svc_params['ech'].echconfiglist.first
end
