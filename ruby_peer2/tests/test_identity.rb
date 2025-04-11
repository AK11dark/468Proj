require 'minitest/autorun'
require 'fileutils'
require 'tempfile'
require_relative '../identity'
require_relative '../cryptography'

class PeerIdentityTest < Minitest::Test
  def setup
    # Create temporary directory for test files
    @test_dir = Dir.mktmpdir
    
    # Redirect identity files to test directory
    Object.const_set(:IDENTITY_PATH, File.join(@test_dir, "identity.json"))
    Object.const_set(:KEY_PATH, File.join(@test_dir, "ecdsa_key.pem"))
    
    @identity = PeerIdentity.new
  end
  
  def teardown
    # Clean up temporary directory after tests
    FileUtils.remove_entry @test_dir
  end
  
  def test_new_identity_creation
    # Simulate user input for username
    simulate_input("testuser") do
      @identity.create_identity
    end
    
    # Verify identity was created properly
    assert_equal "testuser", @identity.username
    assert_instance_of OpenSSL::PKey::EC, @identity.key
    assert @identity.key.private_key?
    
    # Verify files were created
    assert File.exist?(IDENTITY_PATH)
    assert File.exist?(KEY_PATH)
    
    # Verify file contents
    identity_data = JSON.parse(File.read(IDENTITY_PATH))
    assert_equal "testuser", identity_data["username"]
    
    # Verify the key can be loaded back
    loaded_key = OpenSSL::PKey::EC.new(File.read(KEY_PATH))
    assert_instance_of OpenSSL::PKey::EC, loaded_key
    assert loaded_key.private_key?
  end
  
  def test_load_existing_identity
    # Create a test identity first
    username = "existing_user"
    key = Cryptography.generate_key
    
    # Write test identity files
    File.write(IDENTITY_PATH, { username: username }.to_json)
    File.write(KEY_PATH, key.to_pem)
    
    # Load the identity
    @identity.setup
    
    # Verify identity was loaded properly
    assert_equal username, @identity.username
    assert_instance_of OpenSSL::PKey::EC, @identity.key
    assert @identity.key.private_key?
  end
  
  def test_identity_payload
    # Setup identity
    simulate_input("payload_user") do
      @identity.create_identity
    end
    
    # Get payload and parse it
    payload = @identity.identity_payload
    data = JSON.parse(payload)
    
    # Verify payload structure
    assert_equal "payload_user", data["username"]
    assert data["public_key"].start_with?("-----BEGIN PUBLIC KEY-----")
    assert data["signature"], "Signature should be present"
    
    # Verify signature is valid
    pub_key = OpenSSL::PKey::EC.new(data["public_key"])
    username_bytes = "payload_user"
    signature = data["signature"]
    
    # Test signature verification indirectly
    assert @identity.key.dsa_verify_asn1(
      OpenSSL::Digest::SHA256.digest(username_bytes), 
      signature
    )
  end
  
  private
  
  # Helper to simulate user input
  def simulate_input(input)
    original_stdin = $stdin
    $stdin = StringIO.new(input)
    yield
  ensure
    $stdin = original_stdin
  end
end 