require 'socket'
require 'json'

server = TCPServer.new('0.0.0.0', 3002)
puts "[Server] Listening on port 3002..."

loop do
  client = server.accept
  request = client.gets&.strip
  puts "[Server] Received: #{request}"

  if request == "LIST"
    files = Dir.entries("shared") - %w[. ..]
    client.puts files.to_json
  elsif request.start_with?("GET ")
    filename = request.split(" ", 2)[1]
    path = File.join("shared", filename)

    if File.exist?(path)
      content = File.read(path)
      client.puts content.bytesize
      client.write content
    else
      client.puts "ERROR: File not found"
    end
  end

  client.close
end
