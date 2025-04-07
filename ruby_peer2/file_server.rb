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
          @session_keys.delete(socket)
          socket.close
        end
      end
    end
  end

  def handle_client(socket)
    command = socket.read(1)

    case command
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
        socket.puts({ status: "ok", message: "Identity verified" }.to_json)
        return true
      else
        puts "❌ Signature invalid!"
        socket.puts({ status: "error", message: "Signature invalid" }.to_json)
        return false
      end

    rescue => e
      puts "❌ Error during verification: #{e}"
      socket.puts({ status: "error", message: "Exception: #{e.message}" }.to_json)
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
end

# Run the server
if __FILE__ == $0
  server = FileServer.new
  server.start
end
