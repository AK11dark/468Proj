# Use AES-GCM to encrypt files, using passwords for access

require 'openssl'
require 'json'
require 'securerandom'
require 'fileutils'

# Password-based key derivation for file encryption
def derive_key_from_password(password, salt = nil)
  # Generate a random salt if not provided
  salt = SecureRandom.random_bytes(16) if salt.nil?
  
  # Use PBKDF2 to derive a key from the password
  iteration_count = 100000
  key_length = 32 # 256 bits for AES-256
  digest = OpenSSL::Digest.new('SHA256')
  
  key = OpenSSL::PKCS5.pbkdf2_hmac(
    password,
    salt,
    iteration_count,
    key_length,
    digest
  )
  
  return key, salt
end

# Encrypt file using AES-GCM
def encrypt_file_with_password(file_path, password)
  # Read the file
  plaintext = File.binread(file_path)
  
  # Derive key from password
  key, salt = derive_key_from_password(password)
  
  # Generate a random IV (nonce)
  iv = SecureRandom.random_bytes(12) # 96 bits as recommended for GCM
  
  # Create the cipher
  cipher = OpenSSL::Cipher.new('aes-256-gcm')
  cipher.encrypt
  cipher.key = key
  cipher.iv = iv
  
  # Encrypt the data
  ciphertext = cipher.update(plaintext) + cipher.final
  
  # Get the authentication tag
  tag = cipher.auth_tag
  
  # Construct the encrypted file path
  encrypted_path = "#{file_path}.enc"
  
  # Store the encrypted data and metadata
  metadata = {
    'salt' => salt.unpack1('H*'),
    'iv' => iv.unpack1('H*'),
    'tag' => tag.unpack1('H*')
  }
  
  # Write the metadata and ciphertext to the encrypted file
  File.open(encrypted_path, 'wb') do |f|
    # Write metadata as JSON
    metadata_bytes = JSON.generate(metadata).encode('utf-8')
    f.write([metadata_bytes.bytesize].pack('N'))
    f.write(metadata_bytes)
    # Write the ciphertext
    f.write(ciphertext)
  end
  
  # Return the path of the encrypted file
  encrypted_path
end

# Decrypt file using AES-GCM
def decrypt_file_with_password(encrypted_path, password, output_path = nil)
  # If output path is not specified, use the original filename without .enc
  output_path ||= encrypted_path.sub(/\.enc$/, '')
  
  # Read the encrypted file
  File.open(encrypted_path, 'rb') do |f|
    # Read metadata length
    metadata_len = f.read(4).unpack1('N')
    # Read metadata
    metadata_bytes = f.read(metadata_len)
    metadata = JSON.parse(metadata_bytes)
    
    # Read the ciphertext
    ciphertext = f.read
    
    # Get metadata values
    salt = [metadata['salt']].pack('H*')
    iv = [metadata['iv']].pack('H*')
    tag = [metadata['tag']].pack('H*')
    
    # Derive key from password and salt
    key, _ = derive_key_from_password(password, salt)
    
    begin
      # Create the cipher for decryption
      cipher = OpenSSL::Cipher.new('aes-256-gcm')
      cipher.decrypt
      cipher.key = key
      cipher.iv = iv
      cipher.auth_tag = tag
      
      # Decrypt the data
      plaintext = cipher.update(ciphertext) + cipher.final
      
      # Write the decrypted data
      File.binwrite(output_path, plaintext)
      
      return output_path
    rescue => e
      puts "Decryption failed: #{e.message}"
      return nil
    end
  end
end

# Get file content without writing to disk
def get_file_content_with_password(encrypted_path, password)
  begin
    # Read the encrypted file
    File.open(encrypted_path, 'rb') do |f|
      # Read metadata length
      metadata_len = f.read(4).unpack1('N')
      # Read metadata
      metadata_bytes = f.read(metadata_len)
      metadata = JSON.parse(metadata_bytes)
      
      # Read the ciphertext
      ciphertext = f.read
      
      # Get metadata values
      salt = [metadata['salt']].pack('H*')
      iv = [metadata['iv']].pack('H*')
      tag = [metadata['tag']].pack('H*')
      
      # Derive key from password and salt
      key, _ = derive_key_from_password(password, salt)
      
      # Create the cipher for decryption
      cipher = OpenSSL::Cipher.new('aes-256-gcm')
      cipher.decrypt
      cipher.key = key
      cipher.iv = iv
      cipher.auth_tag = tag
      
      # Decrypt the data
      plaintext = cipher.update(ciphertext) + cipher.final
      
      return plaintext
    end
  rescue => e
    puts "Decryption failed: #{e.message}"
    return nil
  end
end

# Secure storage manager for handling encrypted files
class SecureStorage
  def initialize(storage_dir = "Received")
    @storage_dir = storage_dir
    FileUtils.mkdir_p(storage_dir) unless Dir.exist?(storage_dir)
  end
  
  def store_encrypted_file(file_content, filename, password)
    # Store file content with encryption
    temp_path = File.join(@storage_dir, "temp_" + filename)
    
    # Write content to temporary file
    File.binwrite(temp_path, file_content)
    
    # Encrypt the file
    encrypted_path = encrypt_file_with_password(temp_path, password)
    
    # Remove the temporary file
    File.delete(temp_path)
    
    # Return path to encrypted file
    encrypted_path
  end
  
  def get_decrypted_file(filename, password, output_path = nil)
    # Decrypt and return file content
    encrypted_path = File.join(@storage_dir, filename)
    encrypted_path += '.enc' unless encrypted_path.end_with?('.enc')
    
    unless File.exist?(encrypted_path)
      puts "File #{encrypted_path} does not exist"
      return nil
    end
    
    # Decrypt the file
    decrypt_file_with_password(encrypted_path, password, output_path)
  end
  
  def get_file_content(filename, password)
    # Get decrypted file content without writing to disk
    encrypted_path = File.join(@storage_dir, filename)
    encrypted_path += '.enc' unless encrypted_path.end_with?('.enc')
    
    unless File.exist?(encrypted_path)
      puts "File #{encrypted_path} does not exist"
      return nil
    end
    
    # Get file content
    get_file_content_with_password(encrypted_path, password)
  end
  
  def list_encrypted_files
    # List all encrypted files in storage directory
    Dir.entries(@storage_dir).select { |f| f.end_with?('.enc') }
  end
  
  def list_all_files
    # List all files in storage directory with their encryption status
    files = Dir.entries(@storage_dir).reject { |f| f == '.' || f == '..' }
    file_info = []
    
    files.each do |filename|
      is_encrypted = filename.end_with?('.enc')
      original_name = is_encrypted ? filename.sub(/\.enc$/, '') : filename
      
      file_info << {
        'filename' => filename,
        'original_name' => original_name,
        'encrypted' => is_encrypted
      }
    end
    
    file_info
  end
end
