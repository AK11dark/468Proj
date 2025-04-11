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
      @ip = local_ip
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
      @socket = UDPSocket.new
      @socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
      
      # Set multicast TTL to ensure multicast packets travel properly
      @socket.setsockopt(Socket::IPPROTO_IP, Socket::IP_MULTICAST_TTL, 255)
      
      # Set the outgoing multicast interface
      @socket.setsockopt(Socket::IPPROTO_IP, Socket::IP_MULTICAST_IF, IPAddr.new(@ip).hton)

      Thread.new do
        announce_loop
      end

      puts "[Advertiser] Announcing #{@service_name} on #{@ip}:#{@port} (discovery) and #{@ip}:#{@network_port} (file transfer)"
    end

    def stop
      @running = false
      @socket&.close
    end

    private

    def announce_loop
      msg = build_mdns_response
      while @running
        begin
          @socket.send(msg, 0, MDNS_ADDR, MDNS_PORT)
          sleep 5
        rescue => e
          puts "[Advertiser] Error: #{e.message}"
          sleep 5
        end
      end
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

    def local_ip
      # Try the standard approach first
      begin
        udp = UDPSocket.new
        udp.connect("8.8.8.8", 1)
        ip = udp.addr.last
        udp.close
        return ip
      rescue => e
        puts "[Advertiser] Warning: Standard IP detection failed: #{e.message}"
      end

      # Fallback method: find a suitable interface
      Socket.ip_address_list.detect do |addr|
        addr.ipv4? && !addr.ipv4_loopback? && !addr.ipv4_multicast?
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
