# -*- encoding: utf-8 -*-
require File.expand_path('../lib/crash_log/auth_hmac/version', __FILE__)

Gem::Specification.new do |gem|
  gem.authors       = ["Ivan Vanderbyl"]
  gem.email         = ["ivan@crashlog.io"]
  gem.description   = %q{A Ruby Gem for authenticating HTTP requests using a HMAC}
  gem.summary       = %q{A Ruby Gem for authenticating HTTP requests using a HMAC}
  gem.homepage      = "http://crashlog.io"

  gem.files         = `git ls-files`.split($\)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.name          = "crashlog-auth-hmac"
  gem.require_paths = ["lib"]
  gem.version       = CrashLog::AuthHMAC::VERSION
end
