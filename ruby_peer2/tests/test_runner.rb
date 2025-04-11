#!/usr/bin/env ruby

# Main test runner script
# Run this script to execute all tests

require 'minitest/autorun'
require 'colorize'

# Load all test files
Dir.glob(File.join(File.dirname(__FILE__), 'test_*.rb')).each do |test_file|
  next if test_file == __FILE__  # Skip the runner itself
  require test_file
end

# Print header before tests run
puts "\n"
puts "========================================".green
puts "      Running Ruby Peer Tests           ".green
puts "========================================".green
puts "\n"

# Let Minitest run the tests

# Print footer after tests complete
at_exit do
  puts "\n"
  puts "========================================".green
  puts "      Test Run Complete                 ".green
  puts "========================================".green
end 