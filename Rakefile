# frozen_string_literal: true

require 'bundler/gem_tasks'
require 'rubocop/rake_task'
require 'rspec/core/rake_task'
require 'openssl'
require 'fileutils'

TMP_DIR    = __dir__ + '/tmp'
CA_KEY     = TMP_DIR + '/ca.key'
CA_CRT     = TMP_DIR + '/ca.crt'
SERVER_KEY = TMP_DIR + '/server.key'
SERVER_CRT = TMP_DIR + '/server.crt'
certs = [CA_KEY, CA_CRT, SERVER_KEY, SERVER_CRT]

directory TMP_DIR

file CA_KEY => TMP_DIR do
  puts "generate #{CA_KEY}..."
  ca_key = OpenSSL::PKey::RSA.generate(2048)
  File.write(CA_KEY, ca_key.to_pem)
end

file CA_CRT => [TMP_DIR, CA_KEY] do
  ca_key = OpenSSL::PKey::RSA.new(File.read(CA_KEY))

  puts "generate #{CA_CRT}..."
  issu = sub = OpenSSL::X509::Name.new
  sub.add_entry('CN', 'test-ca')

  ca_crt = OpenSSL::X509::Certificate.new
  ca_crt.not_before = Time.now
  ca_crt.not_after = Time.now + (60 * 60 * 24 * 365 * 10)
  ca_crt.public_key = ca_key.public_key
  ca_crt.serial = OpenSSL::BN.rand(64)
  ca_crt.version = 2
  ca_crt.issuer = issu
  ca_crt.subject = sub

  factory = OpenSSL::X509::ExtensionFactory.new
  factory.subject_certificate = ca_crt
  factory.issuer_certificate = ca_crt
  ca_crt.add_extension(
    factory.create_extension(
      'keyUsage',
      'critical, cRLSign, keyCertSign'
    )
  )
  ca_crt.add_extension(
    factory.create_extension(
      'basicConstraints',
      'critical, CA:true'
    )
  )
  ca_crt.add_extension(
    factory.create_extension(
      'subjectKeyIdentifier',
      'hash'
    )
  )

  digest = OpenSSL::Digest::SHA256.new
  ca_crt.sign(ca_key, digest)
  File.write(CA_CRT, ca_crt.to_pem)
end

file SERVER_KEY => TMP_DIR do
  puts "generate #{SERVER_KEY}..."
  server_key = OpenSSL::PKey::RSA.generate(2048)
  File.write(SERVER_KEY, server_key.to_pem)
end

file SERVER_CRT => [TMP_DIR, CA_CRT, SERVER_KEY] do
  ca_key = OpenSSL::PKey::RSA.new(File.read(CA_KEY))
  ca_crt = OpenSSL::X509::Certificate.new(File.read(CA_CRT))
  server_key = OpenSSL::PKey::RSA.new(File.read(SERVER_KEY))

  puts "generate #{SERVER_CRT}..."
  sub = OpenSSL::X509::Name.new
  sub.add_entry('CN', 'localhost')

  server_crt = OpenSSL::X509::Certificate.new
  server_crt.not_before = Time.now
  server_crt.not_after = Time.now + (60 * 60 * 24 * 365)
  server_crt.public_key = server_key.public_key
  server_crt.serial = OpenSSL::BN.rand(64)
  server_crt.version = 2
  server_crt.issuer = ca_crt.issuer
  server_crt.subject = sub

  factory = OpenSSL::X509::ExtensionFactory.new
  factory.subject_certificate = server_crt
  factory.issuer_certificate = ca_crt
  server_crt.add_extension(
    factory.create_extension(
      'basicConstraints',
      'CA:FALSE'
    )
  )
  server_crt.add_extension(
    factory.create_extension(
      'keyUsage',
      'digitalSignature, keyEncipherment'
    )
  )
  server_crt.add_extension(
    factory.create_extension(
      'subjectAltName',
      'DNS:localhost'
    )
  )

  digest = OpenSSL::Digest::SHA256.new
  server_crt.sign(ca_key, digest)
  File.write(SERVER_CRT, server_crt.to_pem)
end

desc 'generate ' + certs.map { |path| File.basename(path) }.join(', ')
task gen_certs: certs

desc 'delete ' + certs.map { |path| File.basename(path) }.join(', ')
task :del_certs do
  certs.each do |path|
    puts "delete #{path}..."
    FileUtils.rm(path, force: true)
  end
end

RuboCop::RakeTask.new
RSpec::Core::RakeTask.new(:spec)

desc 'interoperability test: TTTLS13::Client'
RSpec::Core::RakeTask.new(:interop_client) do |t|
  t.pattern = Dir.glob('interop/client_spec.rb')
end

desc 'interoperability test: TTTLS13::Server'
RSpec::Core::RakeTask.new(:interop_server) do |t|
  t.pattern = Dir.glob('interop/server_spec.rb')
end

desc 'interoperability test between openssl'
task interop: %i[interop_client interop_server]

task default: %i[rubocop spec]
