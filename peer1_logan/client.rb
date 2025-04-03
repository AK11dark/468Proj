require 'socket'
require 'json'

peers = JSON.parse(File.read("peers.json"))

puts "running"

peers.each do |peer|
  #next if peer["name"] == "peer1-ruby"

  begin
    puts "\n📡 Connecting to #{peer["name"]} at #{peer["host"]}:#{peer["port"]}"

    socket = TCPSocket.new(peer["host"], peer["port"])
    socket.puts "LIST"
    response = socket.gets
    files = JSON.parse(response)
    puts "Available files: #{files}"

    file_to_get = files.first
    if file_to_get
      puts "⬇️  Requesting file: #{file_to_get}"
      socket = TCPSocket.new(peer["host"], peer["port"])
      socket.puts "GET #{file_to_get}"
      size = socket.gets.to_i
      content = socket.read(size)
      File.write("downloads/#{file_to_get}", content)
      puts "✅ Saved to downloads/#{file_to_get}"
    end

    socket.close
  rescue => e
    puts "❌ Failed to connect: #{e.message}"
  end
end
