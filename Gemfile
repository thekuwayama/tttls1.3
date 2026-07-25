# frozen_string_literal: true

source 'https://rubygems.org'

# ech_auth extensions are expected in ech_config 0.0.6 (unreleased); pin the commit until released
gem 'ech_config', github: 'thekuwayama/ech_config',
                  ref: '8e3a3fd16e317697ac345c55c085ffe6740cfa71'
gem 'logger'
# OpenSSL::HPKE is expected in openssl 4.0.3 (unreleased); use master until available
gem 'openssl', github: 'ruby/openssl'

group :development do
  gem 'base64'
  gem 'byebug'
  gem 'http_parser.rb'
  gem 'rake'
  gem 'resolv', '>= 0.6.2'
  gem 'rspec'
  gem 'rubocop', '1.82.1'
  gem 'webrick'
end

gemspec
