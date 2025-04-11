require "socket"
require "resolv"
require 'ipaddr'

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
    discovered_peers = {}

    begin
      # Configure socket for multicast traffic
      socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
      
      # For Windows compatibility
      if RUBY_PLATFORM =~ /mswin|mingw|cygwin/
        socket.setsockopt(Socket::IPPROTO_IP, Socket::IP_MULTICAST_TTL, 4)
      else
        socket.setsockopt(Socket::IPPROTO_IP, Socket::IP_MULTICAST_TTL, 4)
        socket.setsockopt(Socket::IPPROTO_IP, Socket::IP_MULTICAST_LOOP, 1)
      end
      
      # Bind to any port on 0.0.0.0 to receive multicast traffic
      socket.bind('0.0.0.0', 0)
      
      # Join multicast group (needed for Ruby-Ruby discovery)
      # This is done without restricting port binding which allows Python discovery too
      ip_mreq = IPAddr.new(MDNS_ADDR).hton + IPAddr.new('0.0.0.0').hton
      socket.setsockopt(Socket::IPPROTO_IP, Socket::IP_ADD_MEMBERSHIP, ip_mreq)
      
      puts "🔍 Joined multicast group #{MDNS_ADDR} for discovery"
      
      # Send PTR query
      query = Resolv::DNS::Message.new(0)
      query.add_question(SERVICE_TYPE, Resolv::DNS::Resource::IN::PTR)
      socket.send(query.encode, 0, MDNS_ADDR, MDNS_PORT)
      
      puts "🔍 Sent discovery query to #{MDNS_ADDR}:#{MDNS_PORT}"

      end_time = Time.now + timeout

      while Time.now < end_time
        readers, = IO.select([socket], [], [], 1)
        next unless readers

        buf, sender = socket.recvfrom(2048)
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

          ip = response.additional.find { |n, _, r| 
            r.is_a?(Resolv::DNS::Resource::IN::A)
          }&.last&.address&.to_s

          # If we couldn't find IP in the A record, try TXT records
          if ip.nil?
            txt = response.additional.find { |n, _, r| 
              r.is_a?(Resolv::DNS::Resource::IN::TXT) && 
              n.to_s == name
            }&.last
            
            if txt
              address_txt = txt.strings.find { |s| s.start_with?('address=') }
              ip = address_txt&.split('=')&.last
            end
          end

          port = response.additional.find { |n, _, r| 
            r.is_a?(Resolv::DNS::Resource::IN::SRV) && 
            n.to_s == name
          }&.last&.port

          if ip && port
            discovered_peers[name] = { name: name, ip: ip, port: port }
            puts "Discovered peer: #{name} @ #{ip}:#{port}"
          end
        end
      end
    ensure
      # Leave multicast group before closing
      begin
        ip_mreq = IPAddr.new(MDNS_ADDR).hton + IPAddr.new('0.0.0.0').hton
        socket.setsockopt(Socket::IPPROTO_IP, Socket::IP_DROP_MEMBERSHIP, ip_mreq)
      rescue
        # Ignore errors when leaving multicast group
      end
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
