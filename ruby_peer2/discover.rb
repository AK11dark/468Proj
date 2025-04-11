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
      
      puts "🔎 Sent mDNS query for #{SERVICE_TYPE}"

      end_time = Time.now + timeout

      while Time.now < end_time
        readers, = IO.select([socket], [], [], 1)
        next unless readers

        buf, sender = socket.recvfrom(4096)  # Increased buffer size
        sender_ip = sender[3]
        puts "📥 Received response from #{sender_ip}"
        
        begin
          response = Resolv::DNS::Message.decode(buf)
          
          # Debug: Print raw response sections
          puts "  📋 Answer records: #{response.answer.length}"
          puts "  📋 Additional records: #{response.additional.length}"
          
          # First check for PTR records in the answer section
          service_names = response.answer.select { |name, ttl, record| 
            record.is_a?(Resolv::DNS::Resource::IN::PTR) && 
            name.to_s == SERVICE_TYPE 
          }.map { |_, _, record| record.name.to_s }
          
          puts "  🔖 Service names in answer: #{service_names.join(', ')}" unless service_names.empty?
          
          # If no PTR records in answer, try looking anywhere in the message (for Python zeroconf compatibility)
          if service_names.empty?
            response.each_resource do |name, ttl, record|
              if record.is_a?(Resolv::DNS::Resource::IN::PTR) && name.to_s == SERVICE_TYPE
                service_names << record.name.to_s
                puts "  🔖 Found service name in other section: #{record.name.to_s}"
              end
            end
          end

          service_names.each do |name|
            next if discovered_peers[name]
            
            # Skip if this is our own service
            if @@own_service_name && name == @@own_service_name
              puts "  ⏩ Skipping own service: #{name}"
              next
            end
            
            # Look for IP and port information in additional records
            ip = nil
            port = nil
            network_port = nil
            target_hostname = nil
            
            # First try to find SRV record for the service and get the target hostname
            response.each_resource do |record_name, ttl, record|
              if record.is_a?(Resolv::DNS::Resource::IN::SRV) && record_name.to_s == name
                port = record.port
                target_hostname = record.target.to_s
                puts "  🔌 Found SRV record for #{name} with port #{port} and target #{target_hostname}"
              end
            end
            
            # Then try to find A record for the hostname we got from SRV
            response.each_resource do |record_name, ttl, record|
              if record.is_a?(Resolv::DNS::Resource::IN::A)
                # Match either the exact hostname or if we didn't find a target
                # This handles cases where the A record might not match exactly what we expect
                if !target_hostname || record_name.to_s == target_hostname || record_name.to_s.include?(name.split('.')[0])
                  ip = record.address.to_s
                  puts "  🖥️ Found A record with IP #{ip} for #{record_name}"
                end
              end
            end
            
            # Try to find TXT record for additional details (Python often includes this)
            response.each_resource do |record_name, ttl, record|
              if record.is_a?(Resolv::DNS::Resource::IN::TXT) && record_name.to_s == name
                puts "  📝 Found TXT record for #{name}"
                record.strings.each do |txt|
                  puts "    - TXT value: #{txt}"
                  if txt.start_with?("network_port=")
                    network_port = txt.split('=')[1]
                    puts "  🌐 Found network_port #{network_port} in TXT record"
                  elsif txt.start_with?("address=")
                    # Sometimes the IP is also in the TXT record
                    txt_ip = txt.split('=')[1]
                    if !ip && txt_ip && !txt_ip.empty?
                      ip = txt_ip
                      puts "  🖥️ Found IP #{ip} in TXT record"
                    end
                  end
                end
              end
            end
            
            # Use network_port if available, otherwise use the regular port
            final_port = network_port ? network_port.to_i : port
            
            if ip && final_port
              discovered_peers[name] = { name: name, ip: ip, port: final_port }
              puts "🎯 Discovered peer: #{name} @ #{ip}:#{final_port}"
            else
              puts "⚠️ Incomplete peer info for #{name}: IP=#{ip}, Port=#{final_port}"
            end
          end
        rescue => e
          puts "❌ Error parsing DNS response: #{e.message}"
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
      
      puts "🔎 Sent enhanced mDNS query for #{SERVICE_TYPE}"

      end_time = Time.now + timeout

      while Time.now < end_time
        readers, = IO.select([socket], [], [], 1)
        next unless readers

        buf, sender = socket.recvfrom(4096)  # Increased buffer size
        sender_ip = sender[3]
        puts "📥 Received enhanced response from #{sender_ip}"
        
        begin
          response = Resolv::DNS::Message.decode(buf)
          
          # Debug: Print raw response sections
          puts "  📋 Answer records: #{response.answer.length}"
          puts "  📋 Additional records: #{response.additional.length}"
          
          # First check for PTR records in the answer section
          service_names = response.answer.select { |name, ttl, record| 
            record.is_a?(Resolv::DNS::Resource::IN::PTR) && 
            name.to_s == SERVICE_TYPE 
          }.map { |_, _, record| record.name.to_s }
          
          puts "  🔖 Service names in answer: #{service_names.join(', ')}" unless service_names.empty?
          
          # If no PTR records in answer, try looking anywhere in the message (for Python zeroconf compatibility)
          if service_names.empty?
            response.each_resource do |name, ttl, record|
              if record.is_a?(Resolv::DNS::Resource::IN::PTR) && name.to_s == SERVICE_TYPE
                service_names << record.name.to_s
                puts "  🔖 Found service name in other section: #{record.name.to_s}"
              end
            end
          end

          service_names.each do |name|
            next if discovered_peers[name]
            
            # Skip if this is our own service
            if @@own_service_name && name == @@own_service_name
              puts "  ⏩ Skipping own service: #{name}"
              next
            end
            
            # Look for IP and port information in additional records
            ip = nil
            port = nil
            network_port = nil
            target_hostname = nil
            
            # First try to find SRV record for the service and get the target hostname
            response.each_resource do |record_name, ttl, record|
              if record.is_a?(Resolv::DNS::Resource::IN::SRV) && record_name.to_s == name
                port = record.port
                target_hostname = record.target.to_s
                puts "  🔌 Found SRV record for #{name} with port #{port} and target #{target_hostname}"
              end
            end
            
            # Then try to find A record for the hostname we got from SRV
            response.each_resource do |record_name, ttl, record|
              if record.is_a?(Resolv::DNS::Resource::IN::A)
                # Match either the exact hostname or if we didn't find a target
                # This handles cases where the A record might not match exactly what we expect
                if !target_hostname || record_name.to_s == target_hostname || record_name.to_s.include?(name.split('.')[0])
                  ip = record.address.to_s
                  puts "  🖥️ Found A record with IP #{ip} for #{record_name}"
                end
              end
            end
            
            # Try to find TXT record for additional details (Python often includes this)
            response.each_resource do |record_name, ttl, record|
              if record.is_a?(Resolv::DNS::Resource::IN::TXT) && record_name.to_s == name
                puts "  📝 Found TXT record for #{name}"
                record.strings.each do |txt|
                  puts "    - TXT value: #{txt}"
                  if txt.start_with?("network_port=")
                    network_port = txt.split('=')[1]
                    puts "  🌐 Found network_port #{network_port} in TXT record"
                  elsif txt.start_with?("address=")
                    # Sometimes the IP is also in the TXT record
                    txt_ip = txt.split('=')[1]
                    if !ip && txt_ip && !txt_ip.empty?
                      ip = txt_ip
                      puts "  🖥️ Found IP #{ip} in TXT record"
                    end
                  end
                end
              end
            end
            
            # Use network_port if available, otherwise use the regular port
            final_port = network_port ? network_port.to_i : port
            
            if ip && final_port
              discovered_peers[name] = { name: name, ip: ip, port: final_port }
              puts "🎯 Discovered peer: #{name} @ #{ip}:#{final_port}"
            else
              puts "⚠️ Incomplete peer info for #{name}: IP=#{ip}, Port=#{final_port}"
            end
          end
        rescue => e
          puts "❌ Error parsing DNS response: #{e.message}"
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

  # Utility method to dump the raw mDNS response for debugging
  def self.debug_mdns_response(timeout = 5)
    socket = UDPSocket.new
    socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
    
    begin
      query = Resolv::DNS::Message.new(0)
      query.add_question(SERVICE_TYPE, Resolv::DNS::Resource::IN::PTR)
      socket.send(query.encode, 0, MDNS_ADDR, MDNS_PORT)
      
      puts "Sent debug mDNS query, waiting for responses..."
      
      end_time = Time.now + timeout
      
      while Time.now < end_time
        readers, = IO.select([socket], [], [], 1)
        next unless readers
        
        buf, sender = socket.recvfrom(4096)
        sender_ip = sender[3]
        puts "\nReceived mDNS response from #{sender_ip} (#{buf.bytesize} bytes)"
        
        begin
          response = Resolv::DNS::Message.decode(buf)
          puts "Message ID: #{response.id}"
          
          puts "\nAnswer Section:"
          response.answer.each do |name, ttl, record|
            puts "  - #{name} (TTL: #{ttl}): #{record.class} - #{record.inspect}"
          end
          
          puts "\nAuthority Section:"
          response.authority.each do |name, ttl, record|
            puts "  - #{name} (TTL: #{ttl}): #{record.class} - #{record.inspect}"
          end
          
          puts "\nAdditional Section:"
          response.additional.each do |name, ttl, record|
            puts "  - #{name} (TTL: #{ttl}): #{record.class} - #{record.inspect}"
          end
          
        rescue => e
          puts "Error parsing raw response: #{e.message}"
        end
      end
    ensure
      socket.close
    end
  end
end

# If running directly:
if __FILE__ == $0
  if ARGV[0] == "--debug"
    PeerFinder.debug_mdns_response
  else
    PeerFinder.discover_peers
  end
end
