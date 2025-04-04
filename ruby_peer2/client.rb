require 'socket'
require 'json'
require 'openssl'
require 'base64'

# Function to request a file from a remote server (Python file server)
def request_file(ip, port, filename)
  # Make the connection to the peer's file server
  socket = TCPSocket.new(ip, port)
  request = {
    "file_name" => filename
  }
  socket.write("F")
  socket.write([request.to_json.bytesize].pack('N')) # Send length of JSON request
  socket.write(request.to_json)

  # Receive the response from the server
  response = socket.read(1)  # Receive the response type (F for file request)
  if response != "F"
    puts "❌ Unexpected response"
    socket.close
    return
  end

  # Get the length of the response
  data_len = socket.read(4).unpack1('N')
  data = JSON.parse(socket.read(data_len))

  if data["status"] == "accepted"
    # Receiving file content
    file_data_len = socket.read(4).unpack1('N')
    file_data = socket.read(file_data_len)

    # Save the file to the local machine
    File.open("Received/#{filename}", 'wb') do |file|
      file.write(file_data)
    end

    puts "✅ File '#{filename}' received and saved."
  else
    puts "❌ Error: #{data["message"]}"
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
  puts "[Ruby Client] 🤝 Raw shared secret: #{shared_secret.unpack1('H*')}"

  # Apply HKDF to shared secret
  begin
    digest = OpenSSL::Digest::SHA256.new
    hkdf_key = OpenSSL::KDF.hkdf(shared_secret, salt: "", info: "p2p-key-exchange", length: 32, hash: digest)
    puts "[Ruby Client] 🧪 Derived key with HKDF: #{hkdf_key.unpack1('H*')}"
  rescue => e
    puts "[Ruby Client] ❌ HKDF derivation failed: #{e.class} - #{e.message}"
  ensure
    socket.close
  end
end