require_relative "discover"      # for advertising
require_relative "advertise"     # for discovering
require_relative "file_server"

# Start file server
Thread.new do
  start_file_server
end

# Start advertising
Thread.new do
  announcer = DNSSD::PeerAnnouncer.new
  announcer.start
end

puts "\n🔁 mDNS advertising started."
puts "📡 mDNS discovery ready."

loop do
  puts "\nMenu:"
  puts "1. Discover peers"
  puts "2. Exit"
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
    puts "\n👋 Exiting."
    exit
  else
    puts "Invalid option"
  end
end
