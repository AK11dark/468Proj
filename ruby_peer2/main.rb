require_relative "discover"      # for discovering
require_relative "advertise"     # for advertising
require_relative "file_server"   # file server logic
require_relative "client"        # Add client for file request
require_relative "identity"
require_relative "storage"       # Add storage for secure file handling
require 'io/console'             # For password input without echoing

# Helper method for password input
def get_password(prompt="Enter password: ")
  print prompt
  password = STDIN.noecho(&:gets).chomp
  puts  # Add a newline after password input
  password
end

# Function to decrypt a stored file
def decrypt_stored_file
  puts "\n🔓 Decrypt File"
  
  # Let user select directory
  puts "\nSelect directory:"
  puts "1. Received directory"
  puts "2. Files directory"
  print "Select option (1-2): "
  dir_choice = gets.chomp
  
  directory = case dir_choice
              when "1" then "Received"
              when "2" then "Files"
              else
                puts "❌ Invalid selection. Defaulting to Received."
                "Received"
              end
  
  # Create storage object with the selected directory
  storage = SecureStorage.new(directory)
  
  # List encrypted files
  encrypted_files = storage.list_encrypted_files
  
  if encrypted_files.empty?
    puts "❌ No encrypted files found in the #{directory} directory."
    return
  end
  
  puts "\n🔐 Encrypted files available in #{directory}:"
  encrypted_files.each_with_index do |filename, idx|
    puts "#{idx + 1}. #{filename}"
  end
  
  begin
    print "Select file to decrypt (number): "
    idx = gets.chomp.to_i - 1
    
    if idx < 0 || idx >= encrypted_files.length
      puts "❌ Invalid selection."
      return
    end
      
    filename = encrypted_files[idx]
    
    # Ask for password
    password = get_password("Enter decryption password: ")
    if password.empty?
      puts "❌ Password cannot be empty."
      return
    end
    
    # Get output path
    output_filename = filename.sub(/\.enc$/, '')
    print "Enter output path (default: #{directory}/#{output_filename}): "
    custom_path = gets.chomp
    
    if custom_path.empty?
      output_path = File.join(directory, output_filename)
    else
      output_path = custom_path
    end
    
    # Decrypt the file
    decrypted_path = storage.get_decrypted_file(filename, password, output_path)
    
    if decrypted_path
      puts "✅ File successfully decrypted to: #{decrypted_path}"
    else
      puts "❌ Decryption failed. Incorrect password or corrupted file."
    end
      
  rescue => e
    puts "❌ Error: #{e.message}"
  end
end

# Function to encrypt an existing file
def encrypt_file
  puts "\n🔒 Encrypt File"
  
  # Let user select directory
  puts "\nSelect directory:"
  puts "1. Received directory"
  puts "2. Files directory"
  print "Select option (1-2): "
  dir_choice = gets.chomp
  
  directory = case dir_choice
              when "1" then "Received"
              when "2" then "Files"
              else
                puts "❌ Invalid selection. Defaulting to Received."
                "Received"
              end
  
  # Check if directory exists and is not empty
  unless Dir.exist?(directory)
    puts "❌ Directory '#{directory}' does not exist."
    return
  end
  
  # Get list of files in the directory
  files = Dir.entries(directory).reject { |f| f == '.' || f == '..' || File.directory?(File.join(directory, f)) }
  
  if files.empty?
    puts "❌ No files found in #{directory} directory."
    return
  end
  
  # Display files
  puts "\nFiles in #{directory} directory:"
  files.each_with_index do |file, index|
    puts "#{index + 1}. #{file}"
  end
  
  # Let user select a file
  print "\nSelect file to encrypt (1-#{files.length}): "
  file_index = gets.chomp.to_i - 1
  
  if file_index < 0 || file_index >= files.length
    puts "❌ Invalid selection."
    return
  end
  
  selected_file = files[file_index]
  file_path = File.join(directory, selected_file)
  
  # Ask for password
  password = get_password("Enter encryption password: ")
  if password.empty?
    puts "❌ Password cannot be empty."
    return
  end
  
  # Confirm password
  confirm_password = get_password("Confirm encryption password: ")
  if password != confirm_password
    puts "❌ Passwords do not match."
    return
  end
  
  # Encrypt the file
  begin
    encrypted_path = encrypt_file_with_password(file_path, password)
    puts "✅ File successfully encrypted to: #{encrypted_path}"
  rescue => e
    puts "❌ Encryption failed: #{e.message}"
  end
end

# Function to list all stored files
def list_all_stored_files
  puts "\n📂 List Files"
  
  # Let user select directory
  puts "\nSelect directory:"
  puts "1. Received directory"
  puts "2. Files directory"
  puts "3. Both directories"
  print "Select option (1-3): "
  dir_choice = gets.chomp
  
  case dir_choice
  when "1"
    list_files_in_directory("Received")
  when "2"
    list_files_in_directory("Files")
  when "3"
    puts "\n📂 Files in both directories:"
    puts "\n--- Received directory ---"
    list_files_in_directory("Received", false)
    puts "\n--- Files directory ---"
    list_files_in_directory("Files", false)
  else
    puts "❌ Invalid selection. Defaulting to Received."
    list_files_in_directory("Received")
  end
end

# Helper function to list files in a directory
def list_files_in_directory(directory, with_header = true)
  # Check if directory exists
  unless Dir.exist?(directory)
    puts "❌ Directory '#{directory}' does not exist."
    return
  end
  
  storage = SecureStorage.new(directory)
  files = storage.list_all_files
  
  if files.empty?
    puts "📂 No files found in #{directory} directory."
    return
  end
  
  if with_header
    puts "\n📂 Files in #{directory}:"
  end
  
  files.each_with_index do |file_info, idx|
    status = file_info['encrypted'] ? "🔒 Encrypted" : "📄 Unencrypted"
    puts "#{idx + 1}. #{file_info['filename']} (#{status})"
  end
end

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
  puts "6. 🔓 Decrypt Stored File"
  puts "7. 🔒 Encrypt a File"
  puts "8. 📂 List Stored Files"
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
        puts "Performing key exchange..."
        # 🧠 Perform identity authentication
        if identity.send_authentication(selected_peer[:ip], selected_peer[:port], session_key)
          puts "Authentication successful."
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
  when "6"
    decrypt_stored_file
  when "7"
    encrypt_file
  when "8"
    list_all_stored_files
  when "0"
    puts "\n👋 Exiting."
    exit
  else
    puts "Invalid option."
  end
end
