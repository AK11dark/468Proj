require 'minitest/autorun'
require 'fileutils'
require 'securerandom'
require 'timeout'
require_relative '../client'
require_relative '../identity'
require_relative '../storage'
require_relative '../cryptography'

# Tests for Ruby-Python interoperability
class PythonInteropTest < Minitest::Test
  def setup
    # These tests require a running Python peer
    @python_peer_ip = ENV['PYTHON_PEER_IP'] || '127.0.0.1'
    @python_peer_port = (ENV['PYTHON_PEER_PORT'] || 5003).to_i
    
    # Create test file in Files directory
    @test_dir = "Files"
    FileUtils.mkdir_p(@test_dir) unless Dir.exist?(@test_dir)
    
    @test_content = "This is a test file for Ruby-Python interoperability. #{SecureRandom.hex(8)}"
    @test_filename = "ruby_test_#{Time.now.to_i}.txt"
    @test_file_path = File.join(@test_dir, @test_filename)
    
    # Check if Python peer is running before proceeding
    check_python_peer
    
    # Set up identity for authentication
    @identity = PeerIdentity.new
    @identity.setup
  end
  
  def teardown
    # Clean up test files
    File.delete(@test_file_path) if File.exist?(@test_file_path)
  end
  
  def check_python_peer
    begin
      socket = TCPSocket.new(@python_peer_ip, @python_peer_port)
      socket.close
    rescue Errno::ECONNREFUSED, Errno::ETIMEDOUT
      skip "Python peer is not running. Run Python peer on #{@python_peer_ip}:#{@python_peer_port} to test interoperability."
    end
  end

  def test_key_exchange_with_python
    # Test key exchange with Python peer
    puts "\n📝 Testing key exchange with Python peer at #{@python_peer_ip}:#{@python_peer_port}"
    
    session_key = nil
    assert_nothing_raised do
      session_key = perform_key_exchange(@python_peer_ip, @python_peer_port)
    end
    
    # Verify we got a session key
    refute_nil session_key, "Session key should not be nil"
    assert_equal 32, session_key.bytesize, "Session key should be 32 bytes (256 bits)"
    
    puts "✅ Successfully performed key exchange with Python peer"
    puts "🔑 Session key (hex): #{session_key.unpack1('H*')}"
    
    session_key
  end
  
  def test_file_list_from_python
    # Test retrieving file list from Python peer
    puts "\n📝 Testing file list retrieval from Python peer"
    
    file_list = nil
    assert_nothing_raised do
      file_list = request_file_list(@python_peer_ip, @python_peer_port)
    end
    
    # Verify we got a file list
    refute_nil file_list, "File list should not be nil"
    assert_kind_of Array, file_list, "File list should be an array"
    
    puts "✅ Successfully retrieved file list from Python peer"
    puts "📋 Files available: #{file_list.inspect}"
    
    file_list
  end
  
  def test_file_transfer_workflow
    # Test complete file transfer workflow
    puts "\n📝 Testing complete file transfer workflow with Python peer"
    
    # 1. Create a test file in the Files directory
    File.write(@test_file_path, @test_content)
    puts "📄 Created test file: #{@test_file_path}"
    
    # 2. Perform key exchange
    session_key = test_key_exchange_with_python
    
    # 3. Check if file is available on Python peer (this will also notify Python of our files)
    test_file_list_from_python
    
    # 4. Wait for the Python peer to request our file (this is simulated, actual test would require user interaction)
    puts "⚠️ NOTE: In a real scenario, you would need to request this file from the Python peer."
    puts "⚠️ This test cannot fully automate the file transfer process as it requires user confirmation."
    puts "✅ Interoperability test workflow completed."
  end

  # This test is marked as skip by default as it requires manual confirmation on the Python side
  def test_request_file_from_python
    skip "This test requires manual confirmation on the Python side"
    
    # Perform key exchange
    session_key = test_key_exchange_with_python
    
    # Get file list to see what's available
    file_list = test_file_list_from_python
    
    # Skip if no files available
    if file_list.empty?
      skip "No files available on Python peer"
    end
    
    # Pick the first file
    file_to_request = if file_list.first.is_a?(Hash)
                        file_list.first["name"]
                      else
                        file_list.first
                      end
    
    puts "📥 Requesting file: #{file_to_request}"
    
    # Request the file
    assert_nothing_raised do
      Timeout.timeout(30) do  # Set a 30-second timeout
        request_file(@python_peer_ip, @python_peer_port, file_to_request, session_key)
      end
    end
    
    # Check if file was received
    received_path = File.join("Received", file_to_request)
    assert File.exist?(received_path), "File should have been received"
    
    puts "✅ Successfully received file from Python peer"
  end
end 