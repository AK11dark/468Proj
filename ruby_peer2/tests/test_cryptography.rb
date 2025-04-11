require 'minitest/autorun'
require_relative '../cryptography'

class CryptographyTest < Minitest::Test
  def setup
    # Generate a key pair for testing
    @key = Cryptography.generate_key
  end

  def test_key_generation
    # Test that key generation produces valid EC key
    assert_instance_of OpenSSL::PKey::EC, @key
    assert_equal Cryptography::CURVE_NAME, @key.group.curve_name
    assert @key.private_key?, "Generated key should have a private key component"
  end

  def test_sign_verify
    # Test signing and verification
    data = "test data to sign"
    signature = Cryptography.sign(@key, data)
    
    # Verify with the same key
    assert Cryptography.verify(@key, data, signature), "Signature verification should succeed"
    
    # Verify with modified data should fail
    assert_equal false, Cryptography.verify(@key, data + "modified", signature)
  end

  def test_public_key_to_pem
    # Test conversion to PEM format
    pem = Cryptography.public_key_to_pem(@key)
    
    # Verify the PEM format starts correctly
    assert_match(/^-----BEGIN PUBLIC KEY-----/, pem)
    assert_match(/-----END PUBLIC KEY-----\n?$/, pem)
    
    # Create a new key from PEM and verify it works
    pub_key = OpenSSL::PKey::EC.new(pem)
    assert_instance_of OpenSSL::PKey::EC, pub_key
    assert_equal false, pub_key.private_key?
  end
  
  def test_key_compatibility
    # Test data signing and verification with different key instances
    data = "compatibility test data"
    
    # Sign with original key
    signature = Cryptography.sign(@key, data)
    
    # Convert to PEM and back
    pem = Cryptography.public_key_to_pem(@key)
    new_pub_key = OpenSSL::PKey::EC.new(pem)
    
    # Verify with the public key loaded from PEM
    assert Cryptography.verify(new_pub_key, data, signature)
  end
end 