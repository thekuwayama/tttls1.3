# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'tttls1.3/version'

Gem::Specification.new do |spec|
  spec.name          = 'tttls1.3'
  spec.version       = TTTLS13::VERSION
  spec.authors       = ['thekuwayama']
  spec.email         = ['thekuwayama@gmail.com']
  spec.summary       = 'TLS 1.3 implementation in Ruby (Tiny Trial TLS1.3 aka tttls1.3)'
  spec.description   = spec.summary
  spec.homepage      = 'https://github.com/thekuwayama/tttls1.3'
  spec.license       = 'MIT'
  spec.required_ruby_version = '>=2.7'

  spec.files         = `git ls-files`.split($INPUT_RECORD_SEPARATOR)
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']

  spec.add_development_dependency 'bundler', '~> 2.0'
  spec.add_dependency             'ech_config'
  spec.add_dependency             'hpke'
  spec.add_dependency             'logger'
  spec.add_dependency             'openssl'
end
