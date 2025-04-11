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
    puts "Setting own service name: #{@@own_service_name}"
  end

  # Original discovery method to maintain compatibility with Python clients
  def self.discover_peers_original(timeout = 10)
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
          end
        end
      end
    ensure
      socket.close
    end

    discovered_peers.values
  end

  # Enhanced discovery method with proper multicast configuration
  def self.discover_peers_enhanced(timeout = 10)
    discovered_peers = {}
    
    # Create a socket with proper multicast configuration
    socket = UDPSocket.new
    
    # Configure socket for multicast
    socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
    
    # On Windows, SO_REUSEPORT might not be available
    if RUBY_PLATFORM !~ /mswin|mingw|cygwin/
      socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1) rescue nil
    end
    
    # Set TTL for multicast packets
    socket.setsockopt(Socket::IPPROTO_IP, Socket::IP_MULTICAST_TTL, 4)
    
    # Allow multicast packets to be received on this interface
    socket.setsockopt(Socket::IPPROTO_IP, Socket::IP_MULTICAST_LOOP, 1)
    
    # Bind to the mDNS port
    socket.bind('0.0.0.0', MDNS_PORT)
    
    # Join the multicast group
    ip_mreq = IPAddr.new(MDNS_ADDR).hton + IPAddr.new('0.0.0.0').hton
    socket.setsockopt(Socket::IPPROTO_IP, Socket::IP_ADD_MEMBERSHIP, ip_mreq)

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
          end
        end
      end
    rescue => e
      puts "Error in enhanced discovery: #{e.message}"
      puts e.backtrace.join("\n")
    ensure
      # Leave the multicast group
      socket.setsockopt(Socket::IPPROTO_IP, Socket::IP_DROP_MEMBERSHIP, ip_mreq) rescue nil
      socket.close
    end

    discovered_peers.values
  end

  # Main discovery method that tries both approaches
  def self.discover_peers(timeout = 10)
    puts "Starting peer discovery..."
    
    # Try enhanced discovery first
    begin
      peers = discover_peers_enhanced(timeout / 2)
      if !peers.empty?
        puts "✅ Enhanced discovery found #{peers.length} peer(s)"
        return peers
      end
    rescue => e
      puts "Enhanced discovery failed: #{e.message}"
    end
    
    # If enhanced discovery fails or finds no peers, fall back to original method
    puts "Falling back to original discovery method..."
    peers = discover_peers_original(timeout / 2)
    
    # Print once at the end
    if peers.empty?
      puts "❌ No peers found."
    else
      puts "✅ Discovered peers:"
      peers.each_with_index do |peer, i|
        puts "#{i + 1}. #{peer[:name]} @ #{peer[:ip]}:#{peer[:port]}"
      end
    end
    
    peers
  end
end

# If running directly:
if __FILE__ == $0
  PeerFinder.discover_peers
end
