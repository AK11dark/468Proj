require "socket"
require "resolv"
require "ipaddr"

module PeerFinder
  MDNS_PORT = 5353
  MDNS_ADDR = "224.0.0.251"
  SERVICE_TYPE = "_peer._tcp.local."
  
  # Store our own service name to avoid self-discovery
  @@own_service_name = nil
  @@own_service_id = nil
  
  def self.set_own_service_name(service_name)
    @@own_service_name = service_name
    # Extract the unique identifier (e.g., "peer-b9ecf4f8" from "peer-b9ecf4f8._peer._tcp.local.")
    if service_name && service_name.match(/^(peer-[a-f0-9]+)/)
      @@own_service_id = $1
      puts "Setting own service ID: #{@@own_service_id}"
    end
    puts "Setting own service name: #{@@own_service_name}"
  end

  def self.discover_peers(timeout = 10)
    socket = UDPSocket.new
    
    # Configure the socket for multicast
    socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
    
    # Bind to the multicast address and port
    socket.bind('0.0.0.0', MDNS_PORT)
    
    # Join the multicast group
    membership = IPAddr.new(MDNS_ADDR).hton + IPAddr.new('0.0.0.0').hton
    socket.setsockopt(Socket::IPPROTO_IP, Socket::IP_ADD_MEMBERSHIP, membership)
    
    discovered_peers = {}
    puts "👀 Starting peer discovery (looking for #{SERVICE_TYPE})"

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
        
        if !service_names.empty?
          puts "📡 Received response with #{service_names.length} services"
        end

        service_names.each do |name|
          next if discovered_peers[name]
          
          puts "🔍 Examining service: #{name}"
          
          # Skip if this is our own service
          if @@own_service_name && name == @@own_service_name
            puts "Skipping own service: #{name}"
            next
          end
          
          # Also check based on the unique service ID, but only for Ruby peers (peer-XXXX format)
          # Python peers have a different format (python-peer) so we shouldn't filter them
          if @@own_service_id && name && name.start_with?("peer-")
            peer_id_match = name.match(/^(peer-[a-f0-9]+)/)
            if peer_id_match && peer_id_match[1] == @@own_service_id
              puts "Skipping own service by ID match: #{name}"
              next
            end
          end

          ip = response.additional.find { |_, _, r| r.is_a?(Resolv::DNS::Resource::IN::A) }&.last&.address&.to_s
          port = response.additional.find { |_, _, r| r.is_a?(Resolv::DNS::Resource::IN::SRV) }&.last&.port

          if ip && port
            discovered_peers[name] = { name: name, ip: ip, port: port }
            puts "Discovered peer: #{name} @ #{ip}:#{port}"
          end
        end
      end
    ensure
      socket.close
    end
    discovered_peers.values
  end
end

# If running directly:
if __FILE__ == $0
  PeerFinder.discover_peers
end
