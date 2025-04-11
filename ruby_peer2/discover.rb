require "socket"
require "resolv"
require "ipaddr"

module PeerFinder
  MDNS_PORT = 5353
  MDNS_ADDR = "224.0.0.251"
  SERVICE_TYPE = "_peer._tcp.local."
  
  # Store our own service name to avoid self-discovery
  @@own_service_name = nil
  
  def self.set_own_service_name(service_name)
    @@own_service_name = service_name
    # Extract the hostname part (peer-XXXXX) for easier comparison
    @@own_hostname = service_name.split("._peer._tcp.local.")[0] if service_name
    puts "Setting own service name: #{@@own_service_name}"
    puts "Own hostname identifier: #{@@own_hostname}"
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
          
          # Extract hostname part for comparison
          hostname = name.split("._peer._tcp.local.")[0]
          
          # Skip if this is our own service by comparing both hostname and full service name
          if (@@own_hostname && hostname == @@own_hostname) || (@@own_service_name && name == @@own_service_name)
            puts "⚠️ Skipping own service: #{name} (#{hostname})"
            next
          end

          # Get additional information from the packet
          ip = nil
          port = nil
          
          # Process all additional records to find IP and port
          response.additional.each do |record_name, ttl, record|
            if record.is_a?(Resolv::DNS::Resource::IN::A) && record_name.to_s.include?(hostname)
              ip = record.address.to_s
            elsif record.is_a?(Resolv::DNS::Resource::IN::SRV) && record_name.to_s == name
              port = record.port
            end
          end

          # Double-check to ensure this isn't our own peer
          own_ip = local_ip()
          if ip == own_ip && hostname == @@own_hostname
            puts "🛑 Filtering own peer by IP and hostname match: #{hostname} @ #{ip}"
            next
          end

          if ip && port
            discovered_peers[name] = { name: name, ip: ip, port: port }
            puts "Discovered peer: #{name} @ #{ip}:#{port}"
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

    # Final filter - remove any peers that match our hostname
    if @@own_hostname
      discovered_peers.reject! do |name, peer|
        hostname_match = name.split("._peer._tcp.local.")[0] == @@own_hostname
        if hostname_match
          puts "🔴 Removing own service from final results: #{name}"
        end
        hostname_match
      end
    end

    discovered_peers.values
  end
  
  # Helper method to get local IP
  def self.local_ip
    # Try the standard approach first
    begin
      udp = UDPSocket.new
      udp.connect("8.8.8.8", 1)
      ip = udp.addr.last
      udp.close
      return ip
    rescue => e
      puts "Warning: Standard IP detection failed: #{e.message}"
    end

    # Fallback method: find a suitable interface
    Socket.ip_address_list.detect do |addr|
      addr.ipv4? && !addr.ipv4_loopback? && !addr.ipv4_multicast?
    end&.ip_address || "127.0.0.1"
  end
end

# If running directly:
if __FILE__ == $0
  PeerFinder.discover_peers
end
