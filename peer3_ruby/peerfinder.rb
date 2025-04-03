require "socket"
require "resolv"

module DNSSD
  MDNS_PORT = 5353
  MDNS_ADDR = "224.0.0.251"

  # Simple mDNS browser for finding peer services
  def self.browse(service_type, timeout = 30, &blk)
    puts "Browsing for: #{service_type}"
    
    socket = UDPSocket.new
    begin
      # Send query
      query = Resolv::DNS::Message.new(0)
      query.add_question(service_type, Resolv::DNS::Resource::IN::PTR)
      socket.send(query.encode, 0, MDNS_ADDR, MDNS_PORT)
      
      # Listen for responses
      discovered_peers = {}
      end_time = Time.now + timeout

      while Time.now < end_time
        readers, = IO.select([socket], [], [], 2)
        next unless readers
        
        buf, = socket.recvfrom(2048)
        response = Resolv::DNS::Message.decode(buf)
        
        # Extract service names from PTR records
        service_names = response.answer.select { |_, _, data| data.is_a?(Resolv::DNS::Resource::IN::PTR) }
                               .map { |_, _, data| data.name.to_s if data.name.to_s.include?('peer') }
                               .compact
        
        service_names.each do |service_name|
          next if discovered_peers[service_name]
          
          # Extract IP and port
          ip = response.additional.find { |_, _, data| data.is_a?(Resolv::DNS::Resource::IN::A) }&.last&.address&.to_s
          port = response.additional.find { |_, _, data| data.is_a?(Resolv::DNS::Resource::IN::SRV) }&.last&.port
          
          if ip && port
            discovered_peers[service_name] = { service_name: service_name, ip: ip, port: port }
            blk.call({ service_name: service_name, ip: ip, port: port })
          end
        end
      end
    ensure
      socket.close
    end
  end
end

if __FILE__ == $0
  service_type = ARGV[0] || "_peer._tcp.local."
  DNSSD.browse(service_type) do |peer|
    puts "\nDiscovered Peer:"
    puts "  Service Name: #{peer[:service_name]}"
    puts "  IP Address:   #{peer[:ip] || 'Unknown'}"
    puts "  Port:         #{peer[:port] || 'Unknown'}"
  end
end