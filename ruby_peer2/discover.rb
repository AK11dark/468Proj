require "socket"
require "resolv"
require "ipaddr"

module PeerFinder
  MDNS_PORT = 5353
  MDNS_ADDR = "224.0.0.251"
  SERVICE_TYPE = "_peer._tcp.local."
  
  # Store our own service name to avoid self-discovery
  @@own_service_name = nil
  @@own_hostname = nil
  @@own_ip = nil
  
  # Extract just the hostname part (peer-XXXXX) from a service name
  def self.extract_hostname(service_name)
    if service_name && service_name.include?('._peer._tcp.local.')
      service_name.split('._peer._tcp.local.')[0]
    else
      service_name
    end
  end
  
  def self.set_own_service_name(service_name)
    @@own_service_name = service_name
    # Extract the hostname part (peer-XXXXX) for easier comparison
    @@own_hostname = extract_hostname(service_name)
    # Also store our own IP address
    @@own_ip = local_ip
    puts "Setting own service name: #{@@own_service_name}"
    puts "Own hostname identifier: #{@@own_hostname}"
    puts "Own IP address: #{@@own_ip}"
  end

  def self.discover_peers(timeout = 10)
    socket = UDPSocket.new
    
    puts "Starting peer discovery (timeout: #{timeout}s)..."
    
    # Configure the socket for multicast
    socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
    
    # Bind to the multicast address and port
    begin
      socket.bind('0.0.0.0', MDNS_PORT)
      puts "✅ Successfully bound to multicast port"
    rescue => e
      puts "⚠️ Could not bind to multicast port: #{e.message}"
      puts "⚠️ Falling back to standard discovery mode"
    end
    
    # Join the multicast group
    begin
      membership = IPAddr.new(MDNS_ADDR).hton + IPAddr.new('0.0.0.0').hton
      socket.setsockopt(Socket::IPPROTO_IP, Socket::IP_ADD_MEMBERSHIP, membership)
      puts "✅ Successfully joined multicast group"
    rescue => e
      puts "⚠️ Could not join multicast group: #{e.message}"
    end
    
    discovered_peers = {}

    begin
      # Send PTR query
      query = Resolv::DNS::Message.new(0)
      query.add_question(SERVICE_TYPE, Resolv::DNS::Resource::IN::PTR)
      socket.send(query.encode, 0, MDNS_ADDR, MDNS_PORT)
      puts "📤 Sent mDNS query for #{SERVICE_TYPE}"

      end_time = Time.now + timeout
      puts "Listening for responses until #{end_time.strftime('%H:%M:%S')}..."

      while Time.now < end_time
        begin
          readers, = IO.select([socket], [], [], 1)
          next unless readers

          buf, sender = socket.recvfrom(4096)
          puts "📥 Received response from #{sender[3]}:#{sender[1]}" 
          
          response = Resolv::DNS::Message.decode(buf)
          
          # Debug: Show packet information
          puts "📦 Packet sections: #{response.answer.size} answer(s), #{response.additional.size} additional record(s)"

          # Get service names
          service_names = response.answer.select { |_, _, r| r.is_a?(Resolv::DNS::Resource::IN::PTR) }
                                       .map { |_, _, r| r.name.to_s }
                                       
          if service_names.empty?
            puts "⚠️ No PTR records found in response"
            next
          end

          puts "🔍 Found service names: #{service_names.join(', ')}"

          service_names.each do |name|
            next if discovered_peers[name]
            
            # Extract hostname part for comparison
            hostname = extract_hostname(name)
            
            # Debug output to check hostname comparison
            puts "🔍 Comparing discovered '#{hostname}' with own '#{@@own_hostname}'"
            
            # Find IP and port in a simpler way
            ip = nil
            port = nil
            
            response.additional.each do |record_name, ttl, record|
              if record.is_a?(Resolv::DNS::Resource::IN::A)
                ip = record.address.to_s
                puts "📍 Found IP address: #{ip} for #{record_name}"
              elsif record.is_a?(Resolv::DNS::Resource::IN::SRV)
                port = record.port
                puts "🔌 Found port: #{port} for #{record_name}"
              end
            end

            # Skip if this peer is actually ourselves
            if ip && port && is_self?(name, ip, port)
              puts "⚠️ FILTERING OUT own service: #{hostname} @ #{ip}:#{port}"
              next
            end

            if ip && port
              discovered_peers[name] = { name: name, ip: ip, port: port }
              puts "✨ Discovered peer: #{name} @ #{ip}:#{port}"
            else
              puts "⚠️ Missing IP or port for #{name}"
            end
          end
        rescue => e
          puts "⚠️ Error processing response: #{e.message}"
          puts e.backtrace.join("\n") if ENV['DEBUG']
        end
      end
    ensure
      socket.close
    end

    puts "Discovery finished! Found #{discovered_peers.size} peer(s)"

    # Final filtering step - remove any discovered services that are actually us
    filtered_peers = discovered_peers.reject do |name, peer|
      is_self = is_self?(name, peer[:ip], peer[:port])
      puts "🧹 Final check: #{name} - Is self? #{is_self}" if is_self
      is_self
    end
    
    if filtered_peers.size != discovered_peers.size
      puts "🔴 Removed own service in final filter step. Before: #{discovered_peers.size}, After: #{filtered_peers.size}"
      discovered_peers = filtered_peers
    end

    # Return the discovered peers
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

  # Determine if a discovered peer is actually ourselves
  def self.is_self?(name, ip, port)
    hostname = extract_hostname(name)
    
    # Check by hostname
    if @@own_hostname && hostname == @@own_hostname
      puts "⛔ Self-match by hostname: #{hostname}"
      return true
    end
    
    # Check by full service name
    if @@own_service_name && name == @@own_service_name
      puts "⛔ Self-match by full service name"
      return true
    end
    
    # Check by IP address
    if @@own_ip && ip == @@own_ip
      puts "⚠️ IP match (#{ip}), checking hostname..."
      # Only consider it a match if the hostname looks like ours (peer-XXXX)
      if hostname.start_with?('peer-') && @@own_hostname.start_with?('peer-')
        puts "⛔ Self-match by IP and hostname pattern"
        return true
      end
    end
    
    # Not ourselves
    return false
  end
end

# If running directly:
if __FILE__ == $0
  PeerFinder.discover_peers
end
