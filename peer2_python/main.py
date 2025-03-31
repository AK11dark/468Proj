import asyncio
import os
from discovery_service import DiscoveryService
from transfer import FileTransfer
from auth import AuthManager
import sys

async def handle_user_input(service, file_transfer, auth_manager):
    """Handle user input while the service is running"""
    while True:
        print("\nCommands:")
        print("1. List all peers")
        print("2. Update shared files")
        print("3. Request file from peer")
        print("4. Send file to peer")
        print("5. Show session keys")
        print("6. Authenticate with peer")
        print("7. Exit")
        try:
            command = await asyncio.get_event_loop().run_in_executor(None, input, "\nEnter command (1-7): ")
            
            if command == "1":
                peers = service.discovery.get_peers()
                if not peers:
                    print("\nNo peers found yet.")
                else:
                    print("\nCurrent Peers:")
                    for peer_id, data in peers.items():
                        print(f"\nPeer ID: {peer_id}")
                        print(f"  Address: {data['address']}")
                        print(f"  Network Port: {data['port']}")
                        print(f"  Discovery Port: {data.get('discovery_port', data['port'])}")
                        if 'files' in data:
                            print(f"  Shared files: {data['files']}")
                        is_verified = auth_manager.is_peer_verified(peer_id)
                        print(f"  Authentication Status: {'✓ Verified' if is_verified else '✗ Not Verified'}")
                        if is_verified:
                            session_key = auth_manager.get_session_key(peer_id)
                            if session_key:
                                print(f"  Session Key: {session_key.hex()[:16]}...")
                        
            elif command == "2":
                files = await asyncio.get_event_loop().run_in_executor(
                    None, input, "\nEnter comma-separated list of files to share: "
                )
                file_list = [f.strip() for f in files.split(",")]
                service.update_files(file_list)
                print(f"\nUpdated shared files: {file_list}")
                
            elif command == "3":
                peers = service.discovery.get_peers()
                if not peers:
                    print("\nNo peers available to request files from.")
                    continue
                    
                print("\nAvailable peers:")
                for peer_id, data in peers.items():
                    print(f"- {peer_id} ({data['address']})")
                    
                peer_id = await asyncio.get_event_loop().run_in_executor(
                    None, input, "\nEnter peer ID: "
                )
                file_name = await asyncio.get_event_loop().run_in_executor(
                    None, input, "Enter file name to request: "
                )
                
                try:
                    success = await file_transfer.request_file(peer_id, file_name)
                    if success:
                        print(f"\n✓ File successfully received from {peer_id}")
                    else:
                        print(f"\n✗ Failed to receive file from {peer_id}")
                except Exception as e:
                    print(f"\n✗ Error requesting file: {e}")
                    
            elif command == "4":
                peers = service.discovery.get_peers()
                if not peers:
                    print("\nNo peers available to send files to.")
                    continue
                    
                print("\nAvailable peers:")
                for peer_id, data in peers.items():
                    print(f"- {peer_id} ({data['address']})")
                    
                peer_id = await asyncio.get_event_loop().run_in_executor(
                    None, input, "\nEnter peer ID: "
                )
                file_name = await asyncio.get_event_loop().run_in_executor(
                    None, input, "Enter file name to send: "
                )
                
                try:
                    success = await file_transfer.send_file(peer_id, file_name)
                    if success:
                        print(f"\n✓ File successfully sent to {peer_id}")
                    else:
                        print(f"\n✗ Failed to send file to {peer_id}")
                except Exception as e:
                    print(f"\n✗ Error sending file: {e}")
                    
            elif command == "5":
                print("\nCurrent Session Keys:")
                peers = service.discovery.get_peers()
                for peer_id, data in peers.items():
                    if auth_manager.is_peer_verified(peer_id):
                        session_key = auth_manager.get_session_key(peer_id)
                        if session_key:
                            print(f"\nPeer: {peer_id}")
                            print(f"  Session Key: {session_key.hex()[:16]}...")
                    
            elif command == "6":
                # Authenticate with a peer
                peers = service.discovery.get_peers()
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
                        peer_name, _ = available_peers[peer_idx]
                        
                        if auth_manager.is_peer_verified(peer_name):
                            print(f"\nAlready authenticated with {peer_name}")
                            continue
                            
                        print(f"\nInitiating authentication with {peer_name}...")
                        # Use file transfer request to initiate authentication
                        success = await file_transfer.request_file(peer_name, "test.txt")
                        
                        if success:
                            print(f"✓ Authentication successful with {peer_name}")
                            session_key = auth_manager.get_session_key(peer_name)
                            if session_key:
                                print(f"  Session key: {session_key.hex()[:16]}...")
                        else:
                            print(f"✗ Authentication failed with {peer_name}")
                    else:
                        print("Invalid peer number")
                except ValueError:
                    print("Invalid input")
                    
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
    file_transfer = FileTransfer(service.discovery, auth_manager, network_port=0)  # Use port 0 for automatic allocation
    
    try:
        # Start services
        print("Starting discovery service...")
        await service.start()
        
        # Make sure service name is set now that the discovery service is started
        print(f"Discovery service name: {service.discovery.service_name}")
        file_transfer.network.service_name = service.discovery.service_name
        
        print("Starting network service...")
        await file_transfer.start()
        print(f"Your service name: {service.discovery.service_name}")
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