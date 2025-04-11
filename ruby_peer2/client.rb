require 'socket'
require 'json'
require 'openssl'
require 'base64'
require 'digest'


def request_file(ip, port, filename, session_key, original_peer_name=nil)
  socket = TCPSocket.new(ip, port)
  request = { "file_name" => filename }
  socket.write("F")
  socket.write([request.to_json.bytesize].pack('N'))
  socket.write(request.to_json)

  # Expect "F" + metadata
  response_type = socket.read(1)
  if response_type != "F"
    puts "❌ Unexpected response"
    socket.close
    return
  end

  # Read status JSON
  response_len = socket.read(4).unpack1('N')
  response = JSON.parse(socket.read(response_len))

  if response["status"] == "accepted"
    # Expect "D" next
    data_type = socket.read(1)
    if data_type != "D"
      puts "❌ Expected file data block"
      socket.close
      return
    end

    # --- Encrypted file parts ---
    iv_len = socket.read(4).unpack1('N')
    iv = socket.read(iv_len)

    tag_len = socket.read(4).unpack1('N')
    tag = socket.read(tag_len)

    ciphertext_len = socket.read(4).unpack1('N')
    ciphertext = socket.read(ciphertext_len)

    # --- Decrypt ---
    cipher = OpenSSL::Cipher.new('aes-256-gcm')
    cipher.decrypt
    cipher.key = session_key
    cipher.iv = iv
    cipher.auth_tag = tag

    begin
      plaintext = cipher.update(ciphertext) + cipher.final
      
      # Verify file hash if original_peer_name is provided
      if original_peer_name
        hash_verified = verify_file_hash(filename, plaintext, original_peer_name)
        if !hash_verified
          puts "⚠️ WARNING: File hash verification failed. The file may have been tampered with."
          print "Do you still want to save this file? (y/n): "
          save_anyway = gets.chomp.downcase
          if save_anyway != 'y'
            puts "❌ File download canceled."
            socket.close
            return
          end
          puts "⚠️ Proceeding with unverified file..."
        end
      end
      
      Dir.mkdir("Received") unless Dir.exist?("Received")
      output_path = File.join("Received", filename)

      File.open(output_path, "wb") do |f|
        f.write(plaintext)
      end
      puts "✅ File received and saved to #{output_path}"
      
      return plaintext  # Return the file content for further processing if needed
    rescue OpenSSL::Cipher::CipherError => e
      puts "❌ Decryption failed: #{e.message}"
    end
  else
    puts "❌ Error: #{response["message"]}"
  end

  socket.close
end



def perform_key_exchange(peer_ip, peer_port)
  puts "[Ruby Client] 🧠 Generating EC key pair..."
  ec = OpenSSL::PKey::EC.generate('prime256v1')
  ec_public_key = ec.public_key

  # Create a public-only version to send
  ec_only_pub = OpenSSL::PKey::EC.new('prime256v1')
  ec_only_pub.public_key = ec_public_key
  pem_only_pub = ec_only_pub.to_pem

  # Connect and initiate key exchange
  socket = TCPSocket.new(peer_ip, peer_port)
  socket.write("K")

  payload = { public_key: pem_only_pub }.to_json
  socket.write([payload.bytesize].pack('N'))
  socket.write(payload)
  puts "[Ruby Client] 📤 Sent public key to #{peer_ip}:#{peer_port}"

  # Receive peer's public key
  resp_len = socket.read(4)&.unpack1('N')
  response = socket.read(resp_len)
  peer_key = OpenSSL::PKey::EC.new(response)
  puts "[Ruby Client] 📥 Received and parsed peer public key."

  # Derive shared secret
  shared_secret = ec.dh_compute_key(peer_key.public_key)


  # Apply HKDF to shared secret
  begin
    digest = OpenSSL::Digest::SHA256.new
    hkdf_key = OpenSSL::KDF.hkdf(shared_secret, salt: "", info: "p2p-key-exchange", length: 32, hash: digest)
    
    return hkdf_key
  rescue => e
    puts "[Ruby Client] ❌ HKDF derivation failed: #{e.class} - #{e.message}"
  ensure
    socket.close
  end
end


def request_file_list(peer_ip, peer_port, peer_name = nil)
  socket = TCPSocket.new(peer_ip, peer_port)
  socket.write("L")  # Send list request

  # Wait for response type
  response_type = socket.read(1)
  if response_type != "L"
    puts "❌ Unexpected response to file list request"
    socket.close
    return
  end

  # Read length-prefixed JSON array
  response_len = socket.read(4).unpack1('N')
  response = socket.read(response_len)
  file_list = JSON.parse(response)

  puts "\n📁 Files available from peer:"
  file_list.each_with_index do |file_info, index|
    if file_info.is_a?(Hash)
      puts "#{index + 1}. #{file_info['name']} (Hash: #{file_info['hash']})"
    else
      # Handle legacy format without hashes
      puts "#{index + 1}. #{file_info}"
    end
  end
  
  # If peer_name is provided, store the file list with hashes in known_peers.json
  if peer_name
    save_peer_file_list(peer_name, file_list)
    puts "💾 Saved file list for peer '#{peer_name}'"
  end

  socket.close
  return file_list
end

def save_peer_file_list(peer_name, file_list)
  # Print current working directory for debugging
  current_dir = Dir.pwd
  puts "Working directory: #{current_dir}"
  
  # File path for known_peers.json
  file_path = File.join(current_dir, 'known_peers.json')
  puts "Will save to: #{file_path}"
  
  # Load existing known_peers.json
  peers_data = {}
  if File.exist?(file_path)
    begin
      peers_data = JSON.parse(File.read(file_path))
      puts "Loaded existing peers data with #{peers_data.size} entries"
    rescue JSON::ParserError
      puts "⚠️ Error parsing existing known_peers.json, will create new file"
    end
  else
    puts "File doesn't exist yet, will create new one"
  end
  
  # Add or update file_list for this peer
  unless peers_data.key?(peer_name)
    peers_data[peer_name] = {}
    puts "Adding new peer: #{peer_name}"
  else
    puts "Updating existing peer: #{peer_name}"
  end
  
  # Keep the public key if it exists
  if peers_data[peer_name].is_a?(String)
    public_key = peers_data[peer_name]
    peers_data[peer_name] = {
      "public_key" => public_key,
      "files" => file_list
    }
  else
    # If it's already a hash, just update the files
    peers_data[peer_name]["files"] = file_list
  end
  
  # Save updated data
  begin
    File.write(file_path, JSON.pretty_generate(peers_data))
  rescue Errno::EACCES
    puts "❌ Permission denied when writing to #{file_path}"
  rescue => e
    puts "❌ Error writing to #{file_path}: #{e.class} - #{e.message}"
  end
rescue => e
  puts "❌ Error saving peer file list: #{e.class} - #{e.message}"
  puts e.backtrace
end

def verify_file_hash(filename, file_content, peer_name)
  # Get absolute path to known_peers.json
  current_dir = Dir.pwd
  file_path = File.join(current_dir, 'known_peers.json')
  
  # Load known_peers.json
  unless File.exist?(file_path)
    puts "❌ known_peers.json does not exist at #{file_path}"
    return false
  end
    
  begin
    peers_data = JSON.parse(File.read(file_path))
    
    # Check if peer exists and has file list
    unless peers_data.key?(peer_name) && 
           peers_data[peer_name].is_a?(Hash) && 
           peers_data[peer_name].key?("files")
      puts "❌ No file list found for peer '#{peer_name}'"
      return false
    end
    
    # Calculate the hash of the received file
    calculated_hash = Digest::SHA256.hexdigest(file_content)
    
    # Check against stored hash
    peers_data[peer_name]["files"].each do |file_info|
      if file_info.is_a?(Hash) && file_info["name"] == filename
        expected_hash = file_info["hash"]
        if calculated_hash == expected_hash
          puts "✅ File hash verified for '#{filename}'"
          return true
        else
          puts "❌ File hash mismatch for '#{filename}'"
          puts "Expected: #{expected_hash}"
          puts "Received: #{calculated_hash}"
          return false
        end
      end
    end
    
    puts "❌ File '#{filename}' not found in peer's file list"
    return false
  rescue => e
    puts "❌ Error verifying file hash: #{e.class} - #{e.message}"
    puts e.backtrace
    return false
  end
end
