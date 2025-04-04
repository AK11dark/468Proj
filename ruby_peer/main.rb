require 'socket'
require 'json'

peer_ip = "10.0.6.205"      # The IP of the Python peer
peer_port = 5000            # The Python peer's network port
filename = "hello.txt"      # File you want to request
session_key = "deadbeef123" # Session key as hex string

begin
  socket = TCPSocket.new(peer_ip, peer_port)

  # Build file request message
  payload = {
    file_name: filename,
    session_key: session_key,
    is_sending: false
  }.to_json

  socket.write("F")                                     # Message type
  socket.write([payload.bytesize].pack("N"))            # Length (4 bytes)
  socket.write(payload)                                 # JSON payload

  # Read response
  resp_type = socket.read(1)
  length = socket.read(4).unpack("N").first
  data = socket.read(length)
  response = JSON.parse(data)

  if response["status"] == "accepted"
    puts "✅ File transfer accepted, waiting for data..."
    # Now wait for the file data (Python side will send it)
    # You need to implement the file receiving logic separately
  else
    puts "❌ Rejected: #{response["message"] || "unknown reason"}"
  end

  socket.close
rescue => e
  puts "❌ Error: #{e}"
end
