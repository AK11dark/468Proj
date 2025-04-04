require 'socket'
require 'json'
require 'fileutils'

ip = "127.0.0.1"
port = 5000
file_name = "hello.txt"
is_sending = false  # set true to send a file to Python

socket = TCPSocket.new(ip, port)

request = {
  file_name: file_name,
  is_sending: is_sending
}

request_json = JSON.dump(request)

socket.write("F")
socket.write([request_json.bytesize].pack('N'))
socket.write(request_json)

resp_type = socket.read(1)
resp_len = socket.read(4).unpack1('N')
resp = JSON.parse(socket.read(resp_len))

if resp["status"] == "accepted"
  if is_sending
    content = File.read("Files/#{file_name}")
    socket.write("D")
    socket.write([content.bytesize].pack('N'))
    socket.write(content)
    puts "✅ Sent file '#{file_name}'"
  else
    dtype = socket.read(1)
    dlen = socket.read(4).unpack1('N')
    data = socket.read(dlen)
    FileUtils.mkdir_p("Received")
    File.write("Received/#{file_name}", data)
    puts "✅ Received file and saved to Received/#{file_name}'"
  end
else
  puts "❌ Request rejected: #{resp["message"]}"
end

socket.close
