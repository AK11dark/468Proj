require "socket"
require "resolv"

module PeerFinder
  MDNS_PORT = 5353
  MDNS_ADDR = "224.0.0.251"
  SERVICE_TYPE = "_peer._tcp.local."
  
  # Store our own service name to avoid self-discovery
  @@own_service_name = nil
  
  def self.set_own_service_name(service_name)
    @@own_service_name = service_name
    puts "Setting own service name: #{@@own_service_name}"
  end

  def self.discover_peers(timeout = 10)
    socket = UDPSocket.new
    socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
    discovered_peers = {}

    begin
      # Send multiple PTR queries for faster response
      query = Resolv::DNS::Message.new(0)
      query.add_question(SERVICE_TYPE, Resolv::DNS::Resource::IN::PTR)
      encoded_query = query.encode
      
      # Send initial burst of queries to increase chances of quick discovery
      3.times do
        socket.send(encoded_query, 0, MDNS_ADDR, MDNS_PORT)
        sleep 0.1 # Small delay between initial queries
      end

      end_time = Time.now + timeout
      check_interval = 0.2 # Shorter polling interval
      next_query_time = Time.now + 1 # Time to send the next query

      while Time.now < end_time
        # Resend query periodically
        if Time.now >= next_query_time
          socket.send(encoded_query, 0, MDNS_ADDR, MDNS_PORT)
          next_query_time = Time.now + 1
        end

        # Use a short select timeout to process responses quickly
        readers, = IO.select([socket], [], [], check_interval)
        next unless readers

        buf, = socket.recvfrom(2048)
        response = Resolv::DNS::Message.decode(buf)

        # Get service names
        service_names = response.answer.select { |_, _, r| r.is_a?(Resolv::DNS::Resource::IN::PTR) }
                                       .map { |_, _, r| r.name.to_s }

        service_names.each do |name|
          next if discovered_peers[name]
          
          # Skip if this is our own service
          if @@own_service_name && name == @@own_service_name
            puts "Skipping own service: #{name}"
            next
          end

          ip = response.additional.find { |_, _, r| r.is_a?(Resolv::DNS::Resource::IN::A) }&.last&.address&.to_s
          port = response.additional.find { |_, _, r| r.is_a?(Resolv::DNS::Resource::IN::SRV) }&.last&.port

          if ip && port
            discovered_peers[name] = { name: name, ip: ip, port: port }
            puts "Discovered peer: #{name} @ #{ip}:#{port}"
            
            # Early termination if we've found at least one peer and waited for a short additional time
            if !discovered_peers.empty? && (Time.now - end_time).abs > (timeout - 2)
              break
            end
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
