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

  def sign_username
    sig = @key.dsa_sign_asn1(@username)
    Base64.strict_encode64(sig)
  end

  def identity_payload
    {
      username: @username,
      public_key: public_key_pem,
      signature: sign_username
    }.to_json
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
