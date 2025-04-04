require 'socket'
require 'json'

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
