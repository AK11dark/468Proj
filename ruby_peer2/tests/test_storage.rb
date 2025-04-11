require 'minitest/autorun'
require 'fileutils'
require 'securerandom'
require_relative '../storage'

class StorageTest < Minitest::Test
  def setup
    # Create temporary directory for test files
    @test_dir = Dir.mktmpdir
    @storage = SecureStorage.new(@test_dir)
    
    # Create a test file
    @test_content = "This is sensitive test content.\nMultiple lines."
    @test_filename = "test_file.txt"
    @test_password = "testpassword123"
    
    # Create a test file in the temporary directory
    @test_file_path = File.join(@test_dir, @test_filename)
    File.write(@test_file_path, @test_content)
  end
  
  def teardown
    # Clean up temporary directory after tests
    FileUtils.remove_entry @test_dir
  end
  
  def test_key_derivation
    # Test that the same password and salt produce the same key
    password = "test_password"
    salt = SecureRandom.random_bytes(16)
    
    key1, salt1 = derive_key_from_password(password, salt)
    key2, salt2 = derive_key_from_password(password, salt)
    
    assert_equal key1, key2
    assert_equal salt1, salt2
    
    # Test that different passwords produce different keys
    different_key, _ = derive_key_from_password("different_password", salt)
    refute_equal key1, different_key
    
    # Test that different salts produce different keys
    different_salt = SecureRandom.random_bytes(16)
    key3, _ = derive_key_from_password(password, different_salt)
    refute_equal key1, key3
  end
  
  def test_file_encryption_decryption
    # Encrypt the test file
    encrypted_path = encrypt_file_with_password(@test_file_path, @test_password)
    
    # Verify encrypted file exists and is different from original
    assert File.exist?(encrypted_path)
    encrypted_content = File.binread(encrypted_path)
    refute_equal @test_content, encrypted_content
    
    # Decrypt the file to a new location
    output_path = File.join(@test_dir, "decrypted_#{@test_filename}")
    decrypted_path = decrypt_file_with_password(encrypted_path, @test_password, output_path)
    
    # Verify decryption succeeded
    assert_equal output_path, decrypted_path
    assert File.exist?(output_path)
    
    # Verify decrypted content matches original
    decrypted_content = File.read(output_path)
    assert_equal @test_content, decrypted_content
    
    # Test decryption with wrong password fails
    bad_decrypt = decrypt_file_with_password(encrypted_path, "wrong_password", File.join(@test_dir, "bad_decrypt.txt"))
    assert_nil bad_decrypt
  end
  
  def test_get_file_content
    # Encrypt the test file
    encrypted_path = encrypt_file_with_password(@test_file_path, @test_password)
    
    # Get file content without writing to disk
    content = get_file_content_with_password(encrypted_path, @test_password)
    assert_equal @test_content, content
    
    # Test with wrong password
    content_bad = get_file_content_with_password(encrypted_path, "wrong_password")
    assert_nil content_bad
  end
  
  def test_secure_storage
    # Store an encrypted file
    content = "Some file content to store securely"
    filename = "stored_file.txt"
    encrypted_path = @storage.store_encrypted_file(content, filename, @test_password)
    
    # Verify file is stored with encryption
    assert File.exist?(encrypted_path), "Encrypted file should exist at #{encrypted_path}"
    assert encrypted_path.end_with?(".enc"), "Encrypted file path should end with .enc"
    
    # List encrypted files to ensure it's in the storage directory
    encrypted_files = @storage.list_encrypted_files
    assert_includes encrypted_files, "#{filename}.enc", "Encrypted file should be in the list of encrypted files"
    
    # Test retrieving file content - with detailed error info
    retrieved_content = @storage.get_file_content(filename, @test_password)
    if retrieved_content.nil?
      # Debug output if content retrieval fails
      puts "DEBUG: File exists? #{File.exist?(encrypted_path)}"
      puts "DEBUG: File size: #{File.size(encrypted_path) rescue 'unknown'}"
      puts "DEBUG: Encrypted path: #{encrypted_path}"
      puts "DEBUG: Files in directory: #{Dir.entries(@test_dir).join(', ')}"
    end
    assert_equal content, retrieved_content, "Retrieved content should match original content"
    
    # Test retrieving file to disk
    output_path = File.join(@test_dir, "retrieved_#{filename}")
    retrieved_path = @storage.get_decrypted_file(filename, @test_password, output_path)
    assert_equal output_path, retrieved_path, "Retrieved path should match output path"
    assert File.exist?(output_path), "Decrypted file should exist"
    assert_equal content, File.read(output_path), "Decrypted content should match original"
    
    # Test listing all files
    all_files = @storage.list_all_files
    file_found = all_files.find { |f| f["filename"] == "#{filename}.enc" }
    assert file_found, "Encrypted file should be in list_all_files result"
    assert_equal filename, file_found["original_name"], "Original name should match filename"
    assert file_found["encrypted"], "File should be marked as encrypted"
  end
end 