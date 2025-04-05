require 'socket'
require 'json'
require 'openssl'
require 'base64'


def request_file(ip, port, filename, session_key)
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
      Dir.mkdir("Received") unless Dir.exist?("Received")
      output_path = File.join("Received", filename)

      File.open(output_path, "wb") do |f|
        f.write(plaintext)
      end
      
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


def request_file_list(peer_ip, peer_port)
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

  if file_list.is_a?(Array)
    puts "\n📁 Files available from peer:"
    file_list.each_with_index do |file, index|
      puts "#{index + 1}. #{file}"
    end
  else
    puts "❌ Invalid response format"
  end

  socket.close
end
