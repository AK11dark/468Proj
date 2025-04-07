require_relative "file_server"
require_relative "advertise"
require_relative "main" # <- your interactive peer client

def start
  puts "Welcome to P2P File Share"
  puts "1. Receive a file"
  puts "2. Send a file (standby to receive file request)"
  print "Select your role (1 or 2): "
  choice = gets.strip

  case choice
  when "1"
    puts "📤 Starting in receiver mode..."
    run_menu # defined in main.rb

  when "2"
    puts "📥 Starting in send mode..."
    advertise_service
    server = FileServer.new
    puts "👋 Press Ctrl+C to stop the server at any time."

    begin
      server.start
    rescue Interrupt
      puts "\n🛑 Shutting down..."
      stop_advertisement
      exit(0)
    end

  else
    puts "❌ Invalid option."
    exit(1)
  end
end

start if __FILE__ == $0
