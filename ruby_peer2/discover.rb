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
      
      # Send a second query for Python clients specifically
      puts "🔎 Sending second query specifically looking for Python clients..."
      socket.send(query.encode, 0, MDNS_ADDR, MDNS_PORT)
      
      # Send a third query specifically looking for Ruby peers
      puts "🔎 Sending query specifically looking for Ruby peers..."
      socket.send(query.encode, 0, MDNS_ADDR, MDNS_PORT)

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
          
          # SPECIAL CHECK FOR PYTHON CLIENTS
          python_service_name = nil
          response.answer.each do |name, ttl, record|
            if record.is_a?(Resolv::DNS::Resource::IN::PTR) && 
               record.name.to_s.include?("python") && 
               record.name.to_s.include?("peer")
              python_service_name = record.name.to_s
              puts "  🐍 Detected Python client: #{python_service_name}"
            end
          end
          
          # SPECIAL CHECK FOR RUBY PEERS
          ruby_service_name = nil
          response.answer.each do |name, ttl, record|
            if record.is_a?(Resolv::DNS::Resource::IN::PTR) && 
               record.name.to_s.include?("peer-") && 
               record.name.to_s.include?("._peer._tcp.local")
              ruby_service_name = record.name.to_s
              puts "  💎 Detected Ruby peer: #{ruby_service_name}"
            end
          end
          
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
          
          # If we found a Python client via the special check, add it to service_names
          if python_service_name && !service_names.include?(python_service_name)
            service_names << python_service_name
            puts "  🐍 Added Python client to service list"
          end
          
          # If we found a Ruby peer via the special check, add it to service_names
          if ruby_service_name && !service_names.include?(ruby_service_name)
            service_names << ruby_service_name
            puts "  💎 Added Ruby peer to service list"
          end

          # Extract all A records, TXT records, and SRV records for easier processing
          ip_map = {}  # hostname -> IP
          port_map = {}  # service_name -> port
          txt_map = {}   # service_name -> {key -> value}
          
          # Gather all the records
          response.each_resource do |record_name, ttl, record|
            name_str = record_name.to_s
            
            if record.is_a?(Resolv::DNS::Resource::IN::A)
              ip_map[name_str] = record.address.to_s
              puts "  🖥️ Stored A record: #{name_str} -> #{record.address.to_s}"
            elsif record.is_a?(Resolv::DNS::Resource::IN::SRV)
              port_map[name_str] = record.port
              puts "  🔌 Stored SRV record: #{name_str} -> #{record.port}"
            elsif record.is_a?(Resolv::DNS::Resource::IN::TXT)
              txt_map[name_str] = {}
              record.strings.each do |txt|
                if txt.include?('=')
                  key, value = txt.split('=', 2)
                  txt_map[name_str][key] = value
                  puts "  📝 Stored TXT data: #{name_str} -> #{key}=#{value}"
                end
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
            
            # Extract base name for flexible matching
            base_name = name.split('.').first
            
            # Find IP
            ip = nil
            # First try from txt record
            if txt_map[name] && txt_map[name]['address']
              ip = txt_map[name]['address']
              puts "  📝 Got IP from TXT record: #{ip}"
            end
            
            # Try to find matching A record if still no IP
            if !ip
              # Try direct service name match
              ip_map.each do |hostname, host_ip|
                if hostname.include?(base_name)
                  ip = host_ip
                  puts "  🔍 Matched hostname #{hostname} to service #{name} with IP: #{ip}"
                  break
                end
              end
            end
            
            # Get port
            port = nil
            # Try from SRV record first
            if port_map[name]
              port = port_map[name]
              puts "  🔌 Got port from SRV: #{port}"
            end
            
            # Try from TXT record network_port
            network_port = nil
            if txt_map[name] && txt_map[name]['network_port']
              network_port = txt_map[name]['network_port'].to_i
              puts "  🌐 Got network_port from TXT: #{network_port}"
            end
            
            # Use network_port if available
            final_port = network_port || port
            
            if ip && final_port
              discovered_peers[name] = { name: name, ip: ip, port: final_port }
              puts "🎯 Discovered peer: #{name} @ #{ip}:#{final_port}"
            else
              puts "⚠️ Incomplete peer info for #{name}: IP=#{ip}, Port=#{final_port}"
            end
          end
        rescue => e
          puts "❌ Error parsing DNS response: #{e.message}"
          puts e.backtrace.join("\n") if e.backtrace
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
    all_peers = {}
    
    # Try enhanced discovery first
    begin
      enhanced_peers = discover_peers_enhanced(timeout / 2)
      enhanced_peers.each do |peer|
        all_peers[peer[:name]] = peer
      end
      puts "✅ Enhanced discovery found #{enhanced_peers.length} peer(s)"
    rescue => e
      puts "Enhanced discovery failed: #{e.message}"
    end
    
    # Always run original method as well to find all types of peers
    puts "Running original discovery method..."
    original_peers = discover_peers_original(timeout / 2)
    original_peers.each do |peer|
      all_peers[peer[:name]] = peer
    end
    
    # Announce our own service to help other Ruby peers find us
    puts "Sending self-announcement to help other peers find us..."
    begin
      # Create a separate socket for announcement
      announce_socket = UDPSocket.new
      announce_socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
      announce_socket.setsockopt(Socket::IPPROTO_IP, Socket::IP_MULTICAST_TTL, 4)
      
      # Send our own PTR record to announce our presence
      # This helps other Ruby peers find us
      3.times do # Send multiple times to increase chance of reception
        announce_socket.send(build_announcement_message, 0, MDNS_ADDR, MDNS_PORT)
        sleep 0.1
      end
      announce_socket.close
    rescue => e
      puts "Self-announcement failed: #{e.message}"
    end
    
    # Print once at the end
    peers = all_peers.values
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

  # Helper method to build a simple announcement message
  # This sends a basic mDNS response that other Ruby peers can detect
  def self.build_announcement_message
    begin
      # Only build if we have our own name
      return nil unless @@own_service_name
      
      msg = Resolv::DNS::Message.new
      msg.qr = 1 # This is a response
      msg.aa = 1 # Authoritative answer
      
      # Add a PTR record for our service
      ptr_name = Resolv::DNS::Name.create(SERVICE_TYPE)
      our_name = Resolv::DNS::Name.create(@@own_service_name)
      msg.add_answer(ptr_name, 120, Resolv::DNS::Resource::IN::PTR.new(our_name))
      
      msg.encode
    rescue => e
      puts "Error building announcement message: #{e.message}"
      nil
    end
  end

  # Utility method to dump the raw mDNS response for debugging
  def self.debug_mdns_response(timeout = 5)
    socket = UDPSocket.new
    socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
    discovered_peers = {}
    
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
          service_names = []
          response.answer.each do |name, ttl, record|
            puts "  - #{name} (TTL: #{ttl}): #{record.class} - #{record.inspect}"
            if record.is_a?(Resolv::DNS::Resource::IN::PTR) && name.to_s == SERVICE_TYPE
              service_name = record.name.to_s
              service_names << service_name
              puts "    ✓ Found service: #{service_name}"
            end
          end
          
          puts "\nAuthority Section:"
          response.authority.each do |name, ttl, record|
            puts "  - #{name} (TTL: #{ttl}): #{record.class} - #{record.inspect}"
          end
          
          puts "\nAdditional Section:"
          ip_map = {}  # Mapping hostnames to IPs
          port_map = {} # Mapping service names to ports
          txt_map = {}  # Mapping service names to TXT data
          
          response.additional.each do |name, ttl, record|
            puts "  - #{name} (TTL: #{ttl}): #{record.class} - #{record.inspect}"
            
            name_str = name.to_s
            
            # Handle SRV records - store port and target
            if record.is_a?(Resolv::DNS::Resource::IN::SRV)
              port_map[name_str] = record.port
              target = record.target.to_s
              puts "    ✓ Found SRV record: #{name_str} → #{record.port}"
            end
            
            # Handle A records - store IP
            if record.is_a?(Resolv::DNS::Resource::IN::A)
              ip_map[name_str] = record.address.to_s
              puts "    ✓ Found A record: #{name_str} → #{record.address}"
            end
            
            # Handle TXT records - store network_port and address
            if record.is_a?(Resolv::DNS::Resource::IN::TXT)
              txt_map[name_str] = {}
              record.strings.each do |txt|
                if txt.include?('=')
                  key, value = txt.split('=', 2)
                  txt_map[name_str][key] = value
                  puts "    ✓ Found TXT data: #{key}=#{value}"
                end
              end
            end
          end
          
          # Process all service names found
          service_names.each do |service_name|
            # Skip if this is our own service
            if @@own_service_name && service_name == @@own_service_name
              puts "⏩ Skipping own service: #{service_name}"
              next
            end
            
            # Extract base name for flexible matching
            base_name = service_name.split('.').first
            
            # Find IP
            ip = nil
            # First try from txt record
            if txt_map[service_name] && txt_map[service_name]['address']
              ip = txt_map[service_name]['address']
              puts "📝 Got IP from TXT record: #{ip}"
            end
            
            # Try to find matching A record if still no IP
            if !ip
              # Try direct service name match
              ip_map.each do |hostname, host_ip|
                if hostname.include?(base_name)
                  ip = host_ip
                  puts "🔍 Matched hostname #{hostname} to service #{service_name} with IP: #{ip}"
                  break
                end
              end
            end
            
            # Get port
            port = nil
            # Try from SRV record first
            if port_map[service_name]
              port = port_map[service_name]
              puts "🔌 Got port from SRV: #{port}"
            end
            
            # Try from TXT record network_port
            network_port = nil
            if txt_map[service_name] && txt_map[service_name]['network_port']
              network_port = txt_map[service_name]['network_port'].to_i
              puts "🌐 Got network_port from TXT: #{network_port}"
            end
            
            # Use network_port if available
            final_port = network_port || port
            
            if ip && final_port
              discovered_peers[service_name] = { name: service_name, ip: ip, port: final_port }
              puts "✅ Successfully parsed peer: #{service_name} @ #{ip}:#{final_port}"
            else
              puts "❌ Incomplete peer info for #{service_name}: IP=#{ip}, Port=#{final_port}"
            end
          end
          
        rescue => e
          puts "Error parsing raw response: #{e.message}"
          puts e.backtrace.join("\n")
        end
      end
    ensure
      socket.close
    end
    
    if discovered_peers.empty?
      puts "No peers found in debug mode"
    else
      puts "\nDiscovered peers (DEBUG):"
      discovered_peers.values.each_with_index do |peer, i|
        puts "#{i + 1}. #{peer[:name]} @ #{peer[:ip]}:#{peer[:port]}"
      end
    end
    
    discovered_peers.values
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
