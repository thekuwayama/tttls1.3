# frozen_string_literal: true

$LOAD_PATH << __dir__ + '/../lib'

require 'base64'
require 'resolv'
require 'socket'
require 'time'
require 'uri'
require 'webrick'

require 'ech_config'
require 'http/parser'

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
  }.transform_values { |v| '<details><summary>' + v + '</summary>%s</details>' }
  transcript.map do |k, v|
    format(m[k], TTTLS13::Convert.obj2html(v.first))
  end.join('<br>')
end

def parse_echconfigs_pem(pem)
  # https://datatracker.ietf.org/doc/html/draft-farrell-tls-pemesni-08#section-3-4
  s = pem.gsub(/-----(BEGIN|END) (ECH CONFIGS|ECHCONFIG)-----/, '')
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

  # https://datatracker.ietf.org/doc/html/draft-ietf-tls-svcb-ech-01#section-6
  ech = 5
  raise "failed to resolve echconfig via #{hostname} HTTPS RR" \
    if rr.first.nil? || rr.first.params[ech].nil?

  octet = rr.first.params[ech].value
  raise 'failed to parse ECHConfigs' \
    unless octet.length == octet.slice(0, 2).unpack1('n') + 2

  ECHConfig.decode_vectors(octet.slice(2..)).first
end
