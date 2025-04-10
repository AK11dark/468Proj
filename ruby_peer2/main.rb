require_relative "discover"      # for discovering
require_relative "advertise"     # for advertising
require_relative "file_server"   # file server logic
require_relative "client"        # Add client for file request
require_relative "identity"
require_relative "storage"       # Add storage for secure file handling"
require 'io/console'             # For password input without echoing
require 'json'

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

# Make sure the known_peers.json file exists
def ensure_known_peers_file_exists
  begin
    current_dir = Dir.pwd
    file_path = File.join(current_dir, 'known_peers.json')
    
    unless File.exist?(file_path)
      puts "Creating known_peers.json file at #{file_path}"
      File.write(file_path, "{}")
      puts "✅ known_peers.json initialized successfully"
    end
    return true
  rescue => e
    puts "❌ Error initializing known_peers.json: #{e.class} - #{e.message}"
    puts e.backtrace
    return false
  end
end

# Ensure known_peers.json file exists at startup
ensure_known_peers_file_exists

# Start OOP FileServer in a thread
file_server = FileServer.new
Thread.new do
  file_server.start
end


# Keep a reference to the announcer so it doesn't get GC'd
announcer = DNSSD::PeerAnnouncer.new

# Store our own service name to prevent self-discovery
PeerFinder.set_own_service_name(announcer.service_name)

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
  puts "9. 🌐 Find File from Alternative Source"
  puts "0. Exit"
  print "> "

  choice = gets.chomp

  case choice
  when "y"
    puts "accept file transfer"
    file_server.handle_file_request(socket, consent=true)
  when "n"
    puts "reject file transfer"
    file_server.handle_file_request(socket, consent=false)
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
          # Get file list first to store hashes
          request_file_list(selected_peer[:ip], selected_peer[:port], selected_peer[:name])
          # ✅ Proceed with file request only if authenticated
          request_file(selected_peer[:ip], selected_peer[:port], filename, session_key, selected_peer[:name])
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
        request_file_list(selected_peer[:ip], selected_peer[:port], selected_peer[:name])
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
  when "9"
    # Finding files from alternative sources with hash verification
    unless File.exist?('known_peers.json')
      puts "❌ No known peers data. Please use option 3 to fetch file lists first."
      next
    end
    
    begin
      # Load known peers to find files
      peers_data = JSON.parse(File.read('known_peers.json'))
      
      # Create a mapping of peers having each file
      available_files = {}
      peers_data.each do |peer_name, peer_info|
        if peer_info.is_a?(Hash) && peer_info.key?('files')
          peer_info['files'].each do |file_info|
            if file_info.is_a?(Hash)
              filename = file_info['name']
              available_files[filename] ||= []
              available_files[filename] << {
                'peer' => peer_name,
                'hash' => file_info['hash']
              }
            end
          end
        end
      end
      
      if available_files.empty?
        puts "❌ No files found in known peers."
        next
      end
      
      # Show available files
      puts "\n📃 Files available from all known peers:"
      file_list = available_files.keys
      file_list.each_with_index do |filename, i|
        peers_with_file = available_files[filename].map { |info| info['peer'] }
        puts "#{i + 1}. #{filename} (Available from: #{peers_with_file.join(', ')})"
      end
      
      # Ask which file to download
      print "\nWhich file do you want to download? (number): "
      file_idx = gets.chomp.to_i - 1
      if file_idx < 0 || file_idx >= file_list.size
        puts "❌ Invalid selection."
        next
      end
      
      filename = file_list[file_idx]
      
      # Show available sources for this file
      puts "\n🌐 Available sources for '#{filename}':"
      sources = available_files[filename]
      sources.each_with_index do |source, i|
        puts "#{i + 1}. #{source['peer']} (Hash: #{source['hash']})"
      end
      
      # Ask which source to use
      print "\nWhich source do you want to use? (number): "
      source_idx = gets.chomp.to_i - 1
      if source_idx < 0 || source_idx >= sources.size
        puts "❌ Invalid selection."
        next
      end
      
      selected_source = sources[source_idx]
      original_peer = selected_source['peer']
      
      # Now find an active peer to download from
      active_peers = PeerFinder.discover_peers(5)
      active_peer_names = active_peers.map { |p| p[:name] }
      
      if active_peer_names.include?(original_peer)
        # Original peer is online, download directly
        puts "✅ Original peer '#{original_peer}' is online. Downloading directly."
        peer = active_peers.find { |p| p[:name] == original_peer }
        
        # Perform key exchange with the peer
        session_key = perform_key_exchange(peer[:ip], peer[:port])
        if session_key.nil?
          puts "❌ Key exchange failed."
          next
        end
        
        identity = PeerIdentity.new
        identity.setup
        if identity.send_authentication(peer[:ip], peer[:port], session_key)
          request_file(peer[:ip], peer[:port], filename, session_key, original_peer)
        else
          puts "❌ Identity verification failed"
        end
      else
        # Original peer is offline, try to find alternative source
        puts "⚠️ Original peer '#{original_peer}' is offline. Looking for alternative sources..."
        
        # Ask which active peer to try
        puts "\n🔍 Active peers that might have the file:"
        active_peers.each_with_index do |peer, i|
          puts "#{i + 1}. #{peer[:name]} @ #{peer[:ip]}:#{peer[:port]}"
        end
        
        print "\nWhich peer to try? (number): "
        peer_idx = gets.chomp.to_i - 1
        if peer_idx < 0 || peer_idx >= active_peers.size
          puts "❌ Invalid selection."
          next
        end
        
        alternative_peer = active_peers[peer_idx]
        
        # Perform key exchange with the alternative peer
        session_key = perform_key_exchange(alternative_peer[:ip], alternative_peer[:port])
        if session_key.nil?
          puts "❌ Key exchange failed."
          next
        end
        
        identity = PeerIdentity.new
        identity.setup
        if identity.send_authentication(alternative_peer[:ip], alternative_peer[:port], session_key)
          puts "⚠️ Downloading from alternative peer '#{alternative_peer[:name]}' with verification against original peer '#{original_peer}'"
          request_file(alternative_peer[:ip], alternative_peer[:port], filename, session_key, original_peer)
        else
          puts "❌ Identity verification failed"
        end
      end
      
    rescue => e
      puts "❌ Error: #{e.message}"
      puts e.backtrace.join("\n")
    end
  when "0"
    puts "\n👋 Exiting."
    exit
  else
    puts "Invalid option."
  end
end
