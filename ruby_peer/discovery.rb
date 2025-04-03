require "socket"
require "resolv"
require "securerandom"
require "ipaddr"

module DNSSD
  MDNS_PORT = 5353
  MDNS_ADDR = "224.0.0.251"

  class PeerAnnouncer
    attr_reader :service_name, :ip, :port, :network_port
    
    def initialize(port: 5000, network_port: 5001)
      @port = port
      @network_port = network_port
      @service_name = "peer-#{SecureRandom.hex(4)}._peer._tcp.local."
      @running = false
      @socket = nil
      
      # Get local IP address
      @ip = Socket.ip_address_list.find { |addr| addr.ipv4? && !addr.ipv4_loopback? }.ip_address
    end
    
    def start
      @running = true
      
      # Create socket for announcing
      @socket = UDPSocket.new
      @socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
      
      # Create announcement message
      @announcement_msg = create_announcement_msg
      
      # Start announcement loop
      Thread.new do
        announce_service
      end
      
      puts "PeerAnnouncer started"
      puts "  Service Name: #{@service_name}"
      puts "  IP: #{@ip}"
      puts "  Port: #{@port}"
      puts "  Network Port: #{@network_port}"
    end
    
    def stop
      @running = false
      @socket.close if @socket
      @socket = nil
    end
    
    private
    
    def announce_service
      while @running
        begin
          # Send announcement
          @socket.send(@announcement_msg, 0, MDNS_ADDR, MDNS_PORT)
          sleep 30  # Announce every 30 seconds
        rescue => e
          puts "Error in announcement: #{e.message}"
          sleep 5  # Wait a bit before retrying
        end
      end
    end
    
    def create_announcement_msg
      # Extract hostname from service name
      hostname = @service_name.split("._peer._tcp.local.")[0]
      
      # Create DNS message for announcement
      msg = Resolv::DNS::Message.new(0)
      msg.qr = 1  # This is a response
      msg.aa = 1  # Authoritative answer
      
      # Add PTR record
      ptr_name = Resolv::DNS::Name.create("_peer._tcp.local.")
      ptr_data = Resolv::DNS::Name.create(@service_name)
      msg.add_answer(ptr_name, 120, Resolv::DNS::Resource::IN::PTR.new(ptr_data))
      
      # Add SRV record
      srv_name = Resolv::DNS::Name.create(@service_name)
      target = Resolv::DNS::Name.create("#{hostname}.local")
      msg.add_additional(srv_name, 120, Resolv::DNS::Resource::IN::SRV.new(0, 0, @port, target))
      
      # Add A record
      a_name = Resolv::DNS::Name.create("#{hostname}.local")
      msg.add_additional(a_name, 120, Resolv::DNS::Resource::IN::A.new(@ip))
      
      # Add TXT record with properties similar to Python client
      txt_data = ["address=#{@ip}", "discovery_port=#{@port}", "network_port=#{@network_port}"]
      txt_name = Resolv::DNS::Name.create(@service_name)
      msg.add_additional(txt_name, 120, Resolv::DNS::Resource::IN::TXT.new(*txt_data))
      
      msg.encode
    end
  end
end

if __FILE__ == $0
  begin
    # Create and start discovery service
    announcer = DNSSD::PeerAnnouncer.new
    announcer.start
    
    # Keep the main thread running
    puts "Press Ctrl+C to exit"
    loop { sleep 1 }
  rescue Interrupt
    puts "Shutting down..."
    announcer.stop if announcer
  end
end