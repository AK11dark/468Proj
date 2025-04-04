require "socket"
require "resolv"

module PeerFinder
  MDNS_PORT = 5353
  MDNS_ADDR = "224.0.0.251"
  SERVICE_TYPE = "_peer._tcp.local."

  def self.discover_peers(timeout = 10)
    socket = UDPSocket.new
    discovered_peers = {}

    begin
      # Send PTR query
      query = Resolv::DNS::Message.new(0)
      query.add_question(SERVICE_TYPE, Resolv::DNS::Resource::IN::PTR)
      socket.send(query.encode, 0, MDNS_ADDR, MDNS_PORT)

      end_time = Time.now + timeout

      while Time.now < end_time
        readers, = IO.select([socket], [], [], 1)
        next unless readers

        buf, = socket.recvfrom(2048)
        response = Resolv::DNS::Message.decode(buf)

        # Get service names
        service_names = response.answer.select { |_, _, r| r.is_a?(Resolv::DNS::Resource::IN::PTR) }
                                       .map { |_, _, r| r.name.to_s }

        service_names.each do |name|
          next if discovered_peers[name]

          ip = response.additional.find { |_, _, r| r.is_a?(Resolv::DNS::Resource::IN::A) }&.last&.address&.to_s
          port = response.additional.find { |_, _, r| r.is_a?(Resolv::DNS::Resource::IN::SRV) }&.last&.port

          if ip && port
            discovered_peers[name] = { name: name, ip: ip, port: port }
            
          end
        end
      end
    ensure
      socket.close
    end

    # Print once at the end
    if discovered_peers.empty?
      puts "❌ No peers found."
    else
      puts "✅ Discovered peers:"
      discovered_peers.each_with_index do |(_, peer), i|
        puts "#{i + 1}. #{peer[:name]} @ #{peer[:ip]}:#{peer[:port]}"
      end
    end

    discovered_peers.values
  end
end

# If running directly:
if __FILE__ == $0
  PeerFinder.discover_peers
end
