require 'socket'
require 'json'
require 'openssl'

class FileServer
  def initialize(host = '0.0.0.0', port = 5001)
    @host = host
    @port = port
    @session_key = nil

  end

  def start
    server = TCPServer.new(@host, @port)
    puts "[Ruby File Server] Listening on #{@host}:#{@port}..."

    loop do
      client = server.accept
      Thread.new(client) do |socket|
        begin
          handle_client(socket)
        ensure
          socket.close
        end
      end
    end
  end

  def handle_client(socket)
    command = socket.read(1)

    case command
    when "M"
      puts "command recieve, peer is migrating key"
      handle_key_migration(socket)
    when "F"
      $run = false
      handle_file_request(socket)
      $run = true
    when "L"
      handle_file_list_request(socket)
    when "K"
      handle_key_exchange(socket)
    when "A"
      puts "\n🟣 'A' command received — starting authentication handler"
      data = socket.recv(4096)
      message = JSON.parse(data)
      verify_identity(message, socket)
    else
      puts "[Ruby File Server] ❓ Unknown command: #{command.inspect}"
    end
  end

  def handle_key_exchange(socket)
    len = socket.read(4).unpack1('N')
    payload = socket.read(len)
    data = JSON.parse(payload)

    peer_pem = data["public_key"]
    peer_key = OpenSSL::PKey::EC.new(peer_pem)

    puts "[Ruby Server] 📥 Received Python's public key."

    # Generate EC key pair
    ec = OpenSSL::PKey::EC.generate('prime256v1')
    shared_secret = ec.dh_compute_key(peer_key.public_key)
    puts "[Ruby Server] 🔐 Shared secret: #{shared_secret.unpack1('H*')}"

    digest = OpenSSL::Digest::SHA256.new
    session_key = OpenSSL::KDF.hkdf(
      shared_secret,
      salt: "",
      info: "p2p-key-exchange",
      length: 32,
      hash: digest
    )
    puts "[Ruby Server] 🧪 Derived session key: #{session_key.unpack1('H*')}"
    @session_key = session_key

    puts "[Ruby Server] ✅ Session key stored for socket."
  puts "[Ruby Server] 🔑 Session Key (hex): #{session_key.unpack1('H*')}"

    # Send our public key back
    pub_key_obj = OpenSSL::PKey::EC.new('prime256v1')
    pub_key_obj.public_key = ec.public_key
    public_key_pem = pub_key_obj.to_pem
    socket.write([public_key_pem.bytesize].pack('N'))
    socket.write(public_key_pem)
    puts "[Ruby Server] 📤 Sent our public key to Python."
  end

  def verify_identity(message, socket)
    username = message["username"]
    public_key_pem = message["public_key"]
    signature_hex = message["signature"]

    puts "👤 Username: #{username}"
    puts "📤 Public Key (PEM):\n#{public_key_pem}"
    puts "📜 Signature (hex): #{signature_hex}"

    session_key = @session_key

    if session_key.nil?
      puts "❌ No session key found for this socket!"
      socket.puts({ status: "error", message: "No session key" }.to_json)
      return false
    end

    puts "🔑 Session Key (hex): #{session_key.unpack1('H*')}"

    begin
      pubkey = OpenSSL::PKey::EC.new(public_key_pem)
      digest = OpenSSL::Digest::SHA256.new
      signature = [signature_hex].pack("H*")

      known_peers = load_known_peers

      if !known_peers.key?(username)
        puts "👋 First-time peer: #{username} — trusting on first use"
        save_known_peer(username, public_key_pem)
      else
        expected = OpenSSL::PKey::EC.new(known_peers[username])
        if expected.to_der != pubkey.to_der
          puts "❌ Public key mismatch for known peer!"
          socket.puts({ status: "error", message: "Public key mismatch" }.to_json)
          return false
        end
      end

      if pubkey.dsa_verify_asn1(digest.digest(session_key), signature)
        puts "✅ Signature verified for #{username}"
        socket.puts "A"
        return true
      else
        puts "❌ Signature invalid!"
        socket.puts"invalid signature"
        return false
      end

    rescue => e
      puts "❌ Error during verification: #{e}"
      socket.puts"unknown error"
      return false
    end
  end

  def load_known_peers
    file = "known_peers.json"
    return {} unless File.exist?(file)
    JSON.parse(File.read(file))
  end

  def save_known_peer(username, public_key_pem)
    peers = load_known_peers
    peers[username] = public_key_pem
    File.write("known_peers.json", JSON.pretty_generate(peers))
  end

  def handle_file_request(socket)
    len = socket.read(4).unpack1("N")
    payload = socket.read(len)
    request = JSON.parse(payload)

    file_name = request["file_name"]
    puts "📥 Peer requested file: #{file_name}"

    file_path = File.join("Files", file_name)

    unless File.exist?(file_path)
      response = { status: "error", message: "File not found" }
      socket.write("F")
      socket.write([response.to_json.bytesize].pack("N"))
      socket.write(response.to_json)
      puts "❌ File not found: #{file_name}"
      return
    end

    puts "accept file transfer? y/n"
    response = STDIN.gets.chomp
    if response == "y"
      puts "✅ File transfer accepted"
    else
      puts "❌ File transfer rejected"
      response = { status: "error", message: "File transfer rejected" }
      socket.write("F")
      socket.write([response.to_json.bytesize].pack("N"))
      socket.write(response.to_json)
      return
    end

    file_data = File.binread(file_path)
    # ✅ Encrypt the file with AES-GCM and the session key
    cipher = OpenSSL::Cipher.new("aes-256-gcm")
    cipher.encrypt
    cipher.key = @session_key
    iv = cipher.random_iv
    cipher.iv = iv

    ciphertext = cipher.update(file_data) + cipher.final
    tag = cipher.auth_tag

    # ✅ Send accepted response
    response = { status: "accepted" }
    socket.write("F")
    socket.write([response.to_json.bytesize].pack("N"))
    socket.write(response.to_json)

    # ✅ Send encrypted data
    socket.write("D")

    socket.write([iv.bytesize].pack("N"))
    socket.write(iv)

    socket.write([tag.bytesize].pack("N"))
    socket.write(tag)

    socket.write([ciphertext.bytesize].pack("N"))
    socket.write(ciphertext)

    puts "🔐 Encrypted file '#{file_name}' sent."
    puts "🔑 IV: #{iv.unpack1('H*')}"
    puts "📎 Tag: #{tag.unpack1('H*')}"
    puts "🧱 Ciphertext size: #{ciphertext.bytesize} bytes"
  end

  def handle_file_list_request(socket)
    dir = "Files"
    unless Dir.exist?(dir)
      Dir.mkdir(dir)
    end

    files = Dir.entries(dir).select { |f| File.file?(File.join(dir, f)) }
    
    # Create a list of files with their hashes
    file_list = files.map do |filename|
      file_path = File.join(dir, filename)
      # Calculate SHA-256 hash of file
      file_hash = calculate_file_hash(file_path)
      { name: filename, hash: file_hash }
    end

    response = file_list.to_json
    socket.write("L")
    socket.write([response.bytesize].pack("N"))
    socket.write(response)

    puts "📃 Sent file list with hashes: #{file_list.inspect}"
  end

  def calculate_file_hash(file_path)
    # Calculate SHA-256 hash of a file
    digest = OpenSSL::Digest::SHA256.new
    File.open(file_path, 'rb') do |f|
      buffer = ""
      # Read the file in chunks to handle large files
      while f.read(4096, buffer)
        digest.update(buffer)
      end
    end
    digest.hexdigest
  end

  def handle_key_migration(socket)
    len = socket.read(4).unpack1("N")
    payload = socket.read(len)
    message = JSON.parse(payload)

    username = message["username"]
    new_key_pem = message["new_key"]
    signature = Base64.decode64(message["signature"])

    puts "🔍 Received new_key PEM:\n#{new_key_pem.inspect}"

    known_peers = load_known_peers

    unless known_peers.key?(username)
      puts "❌ Cannot migrate unknown peer: #{username}"
      socket.write("R")
      return
    end

    old_key = OpenSSL::PKey::EC.new(known_peers[username])

    begin
      # ✅ FIX: verify signature over raw new_key_pem (not hashed)
      valid = old_key.dsa_verify_asn1(new_key_pem, signature)

      if valid
        puts "✅ Signature verified for key migration of #{username}"
        known_peers[username] = new_key_pem
        save_known_peer(username, new_key_pem)
        socket.write("M")
      else
        puts "❌ Signature verification failed for #{username}"
        socket.write("R")
      end
    rescue => e
      puts "❌ Exception during migration verification: #{e}"
      socket.write("R")
    end
  end
end

# Run the server
if __FILE__ == $0
  server = FileServer.new
  server.start
end
