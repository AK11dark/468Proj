require "socket"
require "resolv"
require "securerandom"
require "ipaddr"

module DNSSD
  MDNS_PORT = 5353
  MDNS_ADDR = "224.0.0.251"

  class PeerAnnouncer
    attr_reader :service_name, :ip, :port, :network_port

    def initialize(port: nil, network_port: nil)
      @port = port || find_available_port
      @network_port = network_port
      @service_name = "peer-#{SecureRandom.hex(4)}._peer._tcp.local."
      @hostname = @service_name.split("._peer._tcp.local.")[0]
      @ip = find_local_ip
      @running = false
    end

    def find_available_port
      server = UDPSocket.new
      server.bind('0.0.0.0', 0)
      port = server.addr[1]
      server.close
      puts "[Advertiser] Selected available port: #{port}"
      port
    end

    def start
      @running = true
      
      # Create and configure the original socket for backward compatibility
      @socket = UDPSocket.new
      @socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
      
      # Create and configure the enhanced socket with proper multicast settings
      @enhanced_socket = UDPSocket.new
      configure_enhanced_socket(@enhanced_socket)

      Thread.new do
        announce_loop
      end

      puts "[Advertiser] Announcing #{@service_name} on #{@ip}:#{@port} (discovery) and #{@ip}:#{@network_port} (file transfer)"
    end

    def stop
      @running = false
      @socket&.close
      @enhanced_socket&.close
    end

    private
    
    def configure_enhanced_socket(socket)
      # Enable address reuse
      socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
      
      # On non-Windows platforms, also set SO_REUSEPORT if available
      if RUBY_PLATFORM !~ /mswin|mingw|cygwin/
        socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1) rescue nil
      end
      
      # Set appropriate TTL (Time To Live) for multicast packets (1-255)
      # 1 = same subnet, 32 = same site, 64 = same region, 128 = same continent, 255 = global
      socket.setsockopt(Socket::IPPROTO_IP, Socket::IP_MULTICAST_TTL, 4)
      
      # Set the multicast interface
      socket.setsockopt(Socket::IPPROTO_IP, Socket::IP_MULTICAST_IF, IPAddr.new(@ip).hton)
      
      # Allow loopback of our own multicast packets (useful for local testing)
      socket.setsockopt(Socket::IPPROTO_IP, Socket::IP_MULTICAST_LOOP, 1)
    end

    def announce_loop
      msg = build_mdns_response
      
      # Send an immediate announcement when we start
      send_announcement(msg)
      
      # Then enter the regular loop
      while @running
        begin
          # Send using both the original and enhanced sockets for maximum compatibility
          send_announcement(msg)
          sleep 2  # More frequent announcements (was 5 seconds)
        rescue => e
          puts "[Advertiser] Error: #{e.message}"
          sleep 2
        end
      end
    end
    
    def send_announcement(msg)
      @socket.send(msg, 0, MDNS_ADDR, MDNS_PORT)
      @enhanced_socket.send(msg, 0, MDNS_ADDR, MDNS_PORT)
      
      # Also send a "goodbye" and "hello" sequence to trigger responses from other peers
      # This is a common technique to force peer refresh
      if rand(5) == 0  # Only do this occasionally to avoid flooding
        puts "[Advertiser] Sending hello/goodbye sequence to refresh peers..."
        begin
          # Build a temporary goodbye message
          goodbye = build_goodbye_message
          @enhanced_socket.send(goodbye, 0, MDNS_ADDR, MDNS_PORT)
          sleep 0.1
          # Then immediately send hello again
          @enhanced_socket.send(msg, 0, MDNS_ADDR, MDNS_PORT)
        rescue => e
          puts "[Advertiser] Error in hello/goodbye sequence: #{e.message}"
        end
      end
    end
    
    def build_goodbye_message
      msg = Resolv::DNS::Message.new
      msg.qr = 1  # response
      msg.aa = 1  # authoritative
      
      ptr = Resolv::DNS::Name.create("_peer._tcp.local.")
      srv = Resolv::DNS::Name.create(@service_name)
      
      # Add a TTL=0 record which signals the peer is going away
      # This can trigger peer refresh mechanisms
      msg.add_answer(ptr, 0, Resolv::DNS::Resource::IN::PTR.new(srv))
      
      msg.encode
    end

    def build_mdns_response
      msg = Resolv::DNS::Message.new
      msg.qr = 1  # response
      msg.aa = 1  # authoritative

      ptr = Resolv::DNS::Name.create("_peer._tcp.local.")
      srv = Resolv::DNS::Name.create(@service_name)
      a = Resolv::DNS::Name.create("#{@hostname}.local")

      msg.add_answer(ptr, 120, Resolv::DNS::Resource::IN::PTR.new(srv))
      msg.add_additional(srv, 120, Resolv::DNS::Resource::IN::SRV.new(0, 0, @port, a))
      msg.add_additional(a, 120, Resolv::DNS::Resource::IN::A.new(@ip))
      msg.add_additional(srv, 120, Resolv::DNS::Resource::IN::TXT.new(
        "address=#{@ip}",
        "discovery_port=#{@port}",
        "network_port=#{@network_port}"
      ))

      msg.encode
    end

    def find_local_ip
      begin
        # Try the primary method first
        ip = primary_ip_detection
        return ip if ip && !ip.empty? && ip != "127.0.0.1"
      rescue => e
        puts "[Advertiser] Primary IP detection failed: #{e.message}. Trying fallback method."
      end
      
      # Fall back to the interface scan method
      fallback_ip_detection
    end
    
    def primary_ip_detection
      # This is the method that was previously used
      udp = UDPSocket.new
      udp.connect("8.8.8.8", 1)
      ip = udp.addr.last
      udp.close
      ip
    end
    
    def fallback_ip_detection
      # Try to find a suitable non-loopback IPv4 address
      Socket.ip_address_list.detect do |addr_info|
        addr_info.ipv4? && !addr_info.ipv4_loopback? && !addr_info.ipv4_multicast?
      end&.ip_address || "127.0.0.1"
    end
  end
end

if __FILE__ == $0
  announcer = DNSSD::PeerAnnouncer.new
  announcer.start

  puts "[Advertiser] Press Ctrl+C to stop"
  begin
    loop { sleep 1 }
  rescue Interrupt
    announcer.stop
    puts "\n[Advertiser] Stopped."
  end
end
