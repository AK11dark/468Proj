require 'socket'
require 'json'

# Load peer info from JSON
peer_info = JSON.parse(File.read('peers.json'))["bob"]
ip = peer_info["ip"]
port = peer_info["port"]

filename = "example.txt"
output_file = "received_from_python.txt"

# Connect to the server
socket = TCPSocket.new(ip, port)
puts "Connected to #{ip}:#{port}"

# Send file request
request = {
  type: "file_request",
  filename: filename,
  from: "ruby-client"
}
socket.puts(request.to_json)

# Get response
response_line = socket.gets
response = JSON.parse(response_line)
puts "Response: #{response["status"]}"

# If accepted, receive the file
if response["status"] == "accepted"
  File.open(output_file, "wb") do |f|
    while chunk = socket.read(1024)
      f.write(chunk)
    end
  end
  puts "File saved to #{output_file}"
else
  puts "Request denied by server."
end

socket.close
