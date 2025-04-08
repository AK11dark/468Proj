# identity.rb
require 'openssl'
require 'json'
require 'base64'
require 'socket'

IDENTITY_PATH = "identity.json"
KEY_PATH = "ecdsa_key.pem"

class PeerIdentity
  attr_reader :username, :key

  def initialize
    @username = nil
    @key = nil
  end

  def setup
    load_or_create_key
    load_or_create_username
  end

  def create_identity
    create_key
    create_username
    puts "\n👤 Your identity information (share with peers):"
    puts "Username: #{@username}"
    puts "Public Key:\n#{public_key_pem}"
  end

  def create_key
    @key = OpenSSL::PKey::EC.generate('prime256v1')
    File.write(KEY_PATH, @key.to_pem)
    puts "🔐 New ECDSA key pair generated and saved."
  end

  def create_username
    print "Enter your username: "
    @username = gets.chomp.strip
    File.write(IDENTITY_PATH, { username: @username }.to_json)
    puts "👤 Username '#{@username}' saved."
  end

  def load_or_create_key
    if File.exist?(KEY_PATH)
      @key = OpenSSL::PKey::EC.new(File.read(KEY_PATH))
    else
      create_key
    end
  end

  def load_or_create_username
    if File.exist?(IDENTITY_PATH)
      data = JSON.parse(File.read(IDENTITY_PATH))
      @username = data["username"]
    else
      create_username
    end
  end

  def public_key_pem
    pub = OpenSSL::PKey::EC.new(@key.group)
    pub.public_key = @key.public_key
    pub.to_pem
  end


  def identity_payload
    {
      username: @username,
      public_key: public_key_pem,
      signature: sign_username
    }.to_json
  end

  def rotate_key
    unless File.exist?(IDENTITY_PATH) && File.exist?(KEY_PATH)
      puts "❌ Identity or private key not found."
      return nil
    end

    # Load current identity info
    identity = JSON.parse(File.read(IDENTITY_PATH))
    username = identity["username"]

    # ✅ Load old private key BEFORE overwriting it
    old_key = OpenSSL::PKey::EC.new(File.read(KEY_PATH))

    # 🔐 Generate new ECDSA key pair
    new_key = OpenSSL::PKey::EC.generate("prime256v1")
    new_pubkey_only = OpenSSL::PKey::EC.new(new_key.group)
    new_pubkey_only.public_key = new_key.public_key

    # ✅ Normalize the new public key PEM to avoid newline issues
    new_pub_pem = new_pubkey_only.to_pem.gsub("\r\n", "\n")

    puts "✍️ new_pub_pem being signed:"
    puts new_pub_pem.inspect
    puts "🔑 SHA256:", OpenSSL::Digest::SHA256.hexdigest(new_pub_pem)

    # ✅ Sign the normalized PEM with old private key using SHA256
    digest = OpenSSL::Digest::SHA256.new
    signature = old_key.dsa_sign_asn1(digest.digest(new_pub_pem))

    # ✅ Now save the new private key and updated identity
    File.write(KEY_PATH, new_key.to_pem)
    File.write(IDENTITY_PATH, JSON.pretty_generate({
      "username" => username,
      "public_key" => new_pub_pem
    }))

    puts "🔁 Key rotation complete. New public key stored."

    {
      "username" => username,
      "new_key" => new_pub_pem,
      "signature" => Base64.strict_encode64(signature)
    }
  end


  # Send authentication payload to peer after ECDH
  def send_authentication(peer_ip, peer_port, session_key)
    digest = OpenSSL::Digest::SHA256.digest(session_key)
    signature = @key.dsa_sign_asn1(digest)

    payload = {
      username: @username,
      public_key: public_key_pem,
      signature: Base64.strict_encode64(signature)
    }.to_json

    socket = TCPSocket.new(peer_ip, peer_port)
    socket.write("A")
    socket.write([payload.bytesize].pack("N"))
    socket.write(payload)

    response = socket.read(1)
    socket.close

    return response == "A"
  rescue => e
    puts "❌ Send of authentication package failed: #{e.message}"
    return false
  end
end