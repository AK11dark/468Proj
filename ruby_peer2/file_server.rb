require 'socket'
require 'json'

def start_file_server
  port = 5001
  server = TCPServer.new("0.0.0.0", port)
  puts "[Ruby Server] Listening on port #{port}..."

  loop do
    client = server.accept
    Thread.new do
      begin
        msg_type = client.read(1)
        data_len = client.read(4)&.unpack1('N')
        data = client.read(data_len)

        if msg_type == "F"
          request = JSON.parse(data)
          file_name = request["file_name"]
          puts "[Ruby Server] 📥 Incoming request for '#{file_name}'"

          path = File.join("Files", file_name)
          if File.exist?(path)
            content = File.read(path)
            client.write("F")
            ack = { status: "accepted" }
            client.write([ack.to_json.bytesize].pack('N'))
            client.write(ack.to_json)

            client.write("D")
            client.write([content.bytesize].pack('N'))
            client.write(content)
            puts "[Ruby Server] ✅ Sent file '#{file_name}'"
          else
            client.write("F")
            response = { status: "rejected", message: "File not found" }
            client.write([response.to_json.bytesize].pack('N'))
            client.write(response.to_json)
            puts "[Ruby Server] ❌ File not found: #{file_name}"
          end
        else
          puts "[Ruby Server] ❓ Unknown message type: #{msg_type.inspect}"
        end
      rescue => e
        puts "[Ruby Server] ❌ Error: #{e}"
      ensure
        client.close
      end
    end
  end
end
