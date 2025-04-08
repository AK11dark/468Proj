require_relative "discover"      # for discovering
require_relative "advertise"     # for advertising
require_relative "file_server"   # file server logic
require_relative "client"        # Add client for file request
require_relative "identity"

# Start OOP FileServer in a thread
file_server = FileServer.new
Thread.new do
  file_server.start
end


# Keep a reference to the announcer so it doesn't get GC'd
announcer = DNSSD::PeerAnnouncer.new

# Start advertising in a thread
Thread.new do
  announcer.start
end

puts "\n🔁 mDNS advertising started."
puts "📡 mDNS discovery ready."

loop do
  puts "\nMenu:"
  puts "1. Discover peers"
  puts "2. Request File"
  puts "3. View File List"
  puts "4. Create an identity to share with peer"
  puts "5. Rotate Identity"

  puts "0. Exit"
  print "> "

  choice = gets.chomp

  case choice
  when "1"
    peers = PeerFinder.discover_peers(5)
    if peers.empty?
      puts "\n⚠️  No peers found."
    else
      puts "\n🔎 Discovered peers:"
      peers.each_with_index do |peer, i|
        puts "#{i + 1}. #{peer[:name]} @ #{peer[:ip]}:#{peer[:port]}"
      end
    end

  when "2"
    peers = PeerFinder.discover_peers(5)
    if peers.empty?
      puts "\n⚠️ No peers found."
    else
      puts "\nChoose a peer to request from:"
      peers.each_with_index do |peer, i|
        puts "#{i + 1}. #{peer[:name]} @ #{peer[:ip]}:#{peer[:port]}"
      end

      print "\nEnter the peer number to request from: "
      peer_number = gets.chomp.to_i - 1

      if peer_number >= 0 && peer_number < peers.length
        selected_peer = peers[peer_number]
        print "\nEnter the filename to request: "
        filename = gets.chomp

        puts "#{selected_peer[:ip]} #{selected_peer[:port]} #{filename}"

        # 🔐 Key exchange for signing
        session_key = perform_key_exchange(selected_peer[:ip], selected_peer[:port])
        #ECDSA key creation + loading of identity information payload to send over
        #session key gets signed using ECDSA here for mutual auth
        identity = PeerIdentity.new
        identity.setup
        puts"asda"
        # 🧠 Perform identity authentication
        if identity.send_authentication(selected_peer[:ip], selected_peer[:port], session_key)
          puts"asdasd"
          # ✅ Proceed with file request only if authenticated
          request_file(selected_peer[:ip], selected_peer[:port], filename, session_key)
        else
          puts "❌ Identity verification failed before file request "
        end
      end
    end
  when "3"
    peers = PeerFinder.discover_peers(5)
    if peers.empty?
      puts "\n⚠️ No peers found."
    else
      puts "\nChoose a peer to request from:"
      peers.each_with_index do |peer, i|
        puts "#{i + 1}. #{peer[:name]} @ #{peer[:ip]}:#{peer[:port]}"
      end

      print "\nEnter the peer number to request from: "
      peer_number = gets.chomp.to_i - 1

      if peer_number >= 0 && peer_number < peers.length
        selected_peer = peers[peer_number]
        puts "\n📡 Requesting file list from #{selected_peer[:ip]}..."
        request_file_list(selected_peer[:ip], selected_peer[:port])
      else
        puts "Invalid selection."
      end
    end
  when "4"
    identity = PeerIdentity.new
    identity.create_identity
  # Add this option to the menu loop
  when "5"
    identity = PeerIdentity.new
    migrate_msg = identity.rotate_key
    
    if migrate_msg.nil?
      puts "❌ Failed to rotate key."
      next
    end

    peers = PeerFinder.discover_peers(5)
    if peers.empty?
      puts "❌ No peers found to notify."
      next
    end

  puts "\nChoose peer(s) to notify:"
  peers.each_with_index do |peer, i|
    puts "#{i + 1}. #{peer[:name]} @ #{peer[:ip]}:#{peer[:port]}"
  end
  print "Enter peer number(s) separated by commas, or 'a' for all: "
  input = gets.chomp

  selected_peers =
    if input.strip.downcase == 'a'
      peers
    else
      begin
        input.split(',').map { |i| peers[i.strip.to_i - 1] }.compact
      rescue
        puts "❌ Invalid selection."
        next
      end
    end

  selected_peers.each do |peer|
    begin
      socket = TCPSocket.new(peer[:ip], peer[:port])
      payload = migrate_msg.to_json
      socket.write("M")
      socket.write([payload.bytesize].pack("N"))
      socket.write(payload)
      response = socket.read(1)

      if response == "M"
        puts "✅ #{peer[:name]} accepted your new key."
      else
        puts "⚠️ #{peer[:name]} rejected your migration."
      end
    rescue => e
      puts "❌ Failed to notify #{peer[:name]}: #{e}"
    ensure
      socket.close if socket
    end
  end
  
  when "0"
    puts "\n👋 Exiting."
    exit
  else
    puts "Invalid option."
  end
end
