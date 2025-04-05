require_relative "discover"      # for discovering
require_relative "advertise"     # for advertising
require_relative "file_server"   # file server logic
require_relative "client"        # Add client for file request

# Start file server in a thread
Thread.new do
  start_file_server
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

        # 🔐 Key exchange + 📂 file request
        session_key = perform_key_exchange(selected_peer[:ip], selected_peer[:port])
        request_file(selected_peer[:ip], selected_peer[:port], filename, session_key)
      else
        puts "Invalid selection."
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

  when "0"
    puts "\n👋 Exiting."
    exit
  else
    puts "Invalid option."
  end
end
