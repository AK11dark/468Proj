require 'socket'
require 'json'

def start_file_server(port = 5001)
  server = TCPServer.new('0.0.0.0', port)
  puts "[Ruby Server] Listening on port #{port}..."

  loop do
    client = server.accept
    begin
      msg_type = client.read(4)
      if msg_type == "PING"
        puts "[Ruby Server] 🔔 Received PING!"
      else
        puts "[Ruby Server] ❓ Unknown message: #{msg_type.inspect}"
      end
    rescue => e
      puts "[Ruby Server] ❌ Error: #{e}"
    ensure
      client.close
    end
  end
end


