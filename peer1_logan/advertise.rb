require "zeroconf"

# Advertise the peer over mDNS as _peer._tcp.local.
Zeroconf.service "_peer._tcp.local.", 3002, "peer1-ruby"

# Keep the script running so the service stays discoverable
puts "📡 Advertising peer1-ruby on _peer._tcp.local.:3002"
sleep
