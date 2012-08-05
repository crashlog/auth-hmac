#!/usr/bin/env rake
require "bundler/gem_tasks"

$: << 'lib'

require "crash_log/auth_hmac"

require 'rake'
require "rspec/core/rake_task"

desc "Run all examples"
RSpec::Core::RakeTask.new

task :default => :spec

