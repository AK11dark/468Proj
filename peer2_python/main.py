import asyncio
import os
from discovery_service import DiscoveryService
from transfer import FileTransfer
from auth import AuthManager
import sys
from network import input_pending  # Import the global flag

async def handle_user_input(service, file_transfer, auth_manager):
    """Handle user input while the service is running"""
    while True:
        # Short delay to ensure other tasks have a chance to run
        await asyncio.sleep(0.1)
        
        # Check if input is pending from another part of the application
        if not input_pending:
            print("\nCommands:")
            print("1. List all peers")
            print("2. Update shared files")
            print("3. Transfer file")
            print("4. Show session keys")
            print("5. Authenticate with peer")
            print("6. Refresh peer information")
            print("7. Exit")
            try:
                command = await asyncio.get_event_loop().run_in_executor(None, input, "\nEnter command (1-7): ")
                
                if command == "1":
                    # Refresh peer info silently
                    await service.refresh_peers_info()
                    
                    peers = service.get_peers()
                    if not peers:
                        print("\nNo peers found yet.")
                    else:
                        print("\nCurrent Peers:")
                        for peer_id, data in peers.items():
                            print(f"\nPeer ID: {peer_id}")
                            print(f"  Address: {data['address']}")
                            print(f"  Network Port: {data['port']}")
                            print(f"  Discovery Port: {data.get('discovery_port', data['port'])}")
                            if 'files' in data and data['files']:
                                print(f"  Shared files:")
                                for file in data['files']:
                                    print(f"    - {file}")
                            else:
                                print(f"  Shared files: None")
                            is_verified = auth_manager.is_peer_verified(peer_id)
                            print(f"  Authentication Status: {'✓ Verified' if is_verified else '✗ Not Verified'}")
                            if is_verified:
                                session_key = auth_manager.get_session_key(peer_id)
                                if session_key:
                                    print(f"  Session Key: {session_key.hex()[:16]}...")
                        
                elif command == "2":
                    print("\nEnter files to share:")
                    print("1. Share existing files")
                    print("2. Create and share a new file")
                    
                    share_option = await asyncio.get_event_loop().run_in_executor(
                        None, input, "\nEnter option (1-2): "
                    )
                    
                    if share_option == "1":
                        files = await asyncio.get_event_loop().run_in_executor(
                            None, input, "\nEnter comma-separated list of files to share: "
                        )
                        file_list = [f.strip() for f in files.split(",")]
                        
                    elif share_option == "2":
                        file_name = await asyncio.get_event_loop().run_in_executor(
                            None, input, "\nEnter file name to create: "
                        )
                        file_content = await asyncio.get_event_loop().run_in_executor(
                            None, input, "Enter content for the file: "
                        )
                        
                        # Ensure Files directory exists
                        os.makedirs("Files", exist_ok=True)
                        
                        # Write the file
                        file_path = os.path.join("Files", file_name)
                        with open(file_path, 'w') as f:
                            f.write(file_content)
                            
                        print(f"\nCreated file {file_path}")
                        file_list = [file_name]
                    else:
                        print("Invalid option")
                        continue
                    
                    # Update shared files
                    await service.update_files(file_list)
                    print(f"\nUpdated shared files: {file_list}")
                    
                    # Force a service update to broadcast the file list
                    try:
                        await service.update_service_info()
                    except Exception as e:
                        print(f"Error updating service info: {e}")
                    
                elif command == "3":
                    # Unified file transfer command
                    # First select the peer
                    peers = service.get_peers()
                    if not peers:
                        print("\nNo peers available.")
                        continue
                        
                    print("\nAvailable peers:")
                    available_peer_ids = list(peers.keys())
                    for i, peer_id in enumerate(available_peer_ids, 1):
                        data = peers[peer_id]
                        print(f"{i}. {peer_id} ({data['address']})")
                        if 'files' in data and data['files']:
                            print(f"   Available files: {data['files']}")
                        else:
                            print("   No files advertised")
                            
                    try:
                        peer_choice = await asyncio.get_event_loop().run_in_executor(
                            None, input, "\nEnter peer number (or full peer ID): "
                        )
                        
                        # Check if the input is a number
                        try:
                            peer_idx = int(peer_choice) - 1
                            if 0 <= peer_idx < len(available_peer_ids):
                                peer_id = available_peer_ids[peer_idx]
                            else:
                                print("Invalid peer number")
                                continue
                        except ValueError:
                            # Input is not a number, treat as a service name
                            peer_id = peer_choice
                            if peer_id not in peers:
                                print(f"Peer {peer_id} not found in the list of available peers")
                                continue
                                
                        # Choose direction (send or receive)
                        direction = await asyncio.get_event_loop().run_in_executor(
                            None, input, "Enter direction (send/receive): "
                        )
                        
                        is_sending = direction.lower().startswith("s")
                        
                        if is_sending:
                            # Show available files in Files directory
                            try:
                                files_dir = "Files"
                                if os.path.exists(files_dir) and os.path.isdir(files_dir):
                                    files = os.listdir(files_dir)
                                    if files:
                                        print("\nAvailable files in Files directory:")
                                        for i, file_name in enumerate(files, 1):
                                            print(f"{i}. {file_name}")
                                        
                                        file_choice = await asyncio.get_event_loop().run_in_executor(
                                            None, input, "\nEnter file number or name: "
                                        )
                                        
                                        # Check if the input is a number
                                        try:
                                            file_idx = int(file_choice) - 1
                                            if 0 <= file_idx < len(files):
                                                file_name = files[file_idx]
                                            else:
                                                print("Invalid file number")
                                                continue
                                        except ValueError:
                                            # Input is not a number, use it as the file name
                                            file_name = file_choice
                                    else:
                                        print("\nNo files available in Files directory.")
                                        continue
                                else:
                                    print("\nFiles directory does not exist.")
                                    continue
                            except Exception as e:
                                print(f"Error listing files: {e}")
                                continue
                        else:
                            # Ask user which file to request
                            file_name = await asyncio.get_event_loop().run_in_executor(
                                None, input, "Enter file name to request: "
                            )
                            
                        # Use the unified transfer method
                        try:
                            success = await file_transfer.transfer_file(peer_id, file_name, is_sending=is_sending)
                            if success:
                                if is_sending:
                                    print(f"\n✓ File successfully sent to {peer_id}")
                                else:
                                    print(f"\n✓ File successfully received from {peer_id}")
                            else:
                                if is_sending:
                                    print(f"\n✗ Failed to send file to {peer_id}")
                                else:
                                    print(f"\n✗ Failed to receive file from {peer_id}")
                        except Exception as e:
                            print(f"\n✗ Error transferring file: {e}")
                            import traceback
                            traceback.print_exc()
                    except ValueError:
                        print("Invalid input")
                    
                elif command == "4":
                    print("\nCurrent Session Keys:")
                    peers = service.get_peers()
                    for peer_id, data in peers.items():
                        if auth_manager.is_peer_verified(peer_id):
                            session_key = auth_manager.get_session_key(peer_id)
                            if session_key:
                                print(f"\nPeer: {peer_id}")
                                print(f"  Session Key: {session_key.hex()[:16]}...")
                    
                elif command == "5":
                    # Authenticate with a peer
                    peers = service.get_peers()
                    if not peers:
                        print("\nNo peers available to authenticate with")
                        continue
                        
                    print("\nAvailable peers:")
                    available_peers = []
                    for i, (service_name, data) in enumerate(peers.items(), 1):
                        available_peers.append((service_name, data))
                        print(f"{i}. {service_name} ({data['address']})")
                        print(f"   Status: {'✓ Already Verified' if auth_manager.is_peer_verified(service_name) else '✗ Not Verified'}")
                    
                    if not available_peers:
                        print("\nNo peers available to authenticate with")
                        continue
                        
                    try:
                        peer_idx = int(input("\nEnter peer number to authenticate with: ")) - 1
                        if 0 <= peer_idx < len(available_peers):
                            peer_name, peer_data = available_peers[peer_idx]
                            
                            if auth_manager.is_peer_verified(peer_name):
                                print(f"\nAlready authenticated with {peer_name}")
                                continue
                                
                            print(f"\nInitiating authentication with {peer_name}...")
                            # Initiate key exchange for authentication
                            session_key = await auth_manager.initiate_key_exchange(peer_data['address'], peer_data['port'], file_transfer.network)
                            
                            if session_key:
                                print(f"✓ Authentication successful with {peer_name}")
                                print(f"  Session key: {session_key.hex()[:16]}...")
                            else:
                                print(f"✗ Authentication failed with {peer_name}")
                        else:
                            print("Invalid peer number")
                    except ValueError:
                        print("Invalid input")
                    
                elif command == "6":
                    print("\nRefreshing peer information...")
                    await service.refresh_peers_info()
                    peers = service.get_peers()
                    print(f"Found {len(peers)} peers")
                    
                elif command == "7":
                    print("\nShutting down...")
                    await service.stop()
                    await file_transfer.stop()
                    sys.exit(0)
                    
            except Exception as e:
                print(f"\nError: {e}")
                import traceback
                traceback.print_exc()

async def main():
    """Main entry point for the peer-to-peer file sharing application"""
    print("\n=== P2P File Sharing with DHE-RSA Authentication ===\n")
    
    # Initialize services with zero configuration for ports
    discovery_port = 5000  # Keep discovery port fixed for now
    service = DiscoveryService(port=discovery_port, auto_print_updates=False)
    auth_manager = AuthManager()
    file_transfer = FileTransfer(service, auth_manager, network_port=0)  # Use port 0 for automatic allocation
    
    try:
        # Start services
        print("Starting discovery service...")
        await service.start()
        
        # Make sure service name is set now that the discovery service is started
        service_name = service.get_service_name()
        print(f"Discovery service name: {service_name}")
        file_transfer.network.service_name = service_name
        
        print("Starting network service...")
        await file_transfer.start()
        print(f"Your service name: {service_name}")
        print(f"Network manager service name: {file_transfer.network.service_name}")
        
        # Start user input handler
        asyncio.create_task(handle_user_input(service, file_transfer, auth_manager))
        
        # Run discovery service
        await service.run()
    finally:
        await service.stop()
        await file_transfer.stop()
        print("Shutdown complete")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nProgram terminated by user")