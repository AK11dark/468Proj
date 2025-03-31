import asyncio
import sys
from discovery_service import DiscoveryService
from transfer import FileTransfer
from auth import AuthManager

async def test_peer(peer_name: str, discovery_port: int):
    """Test a single peer instance"""
    print(f"\nStarting peer: {peer_name}")
    print(f"Discovery port: {discovery_port}")
    
    service = None
    file_transfer = None
    auth_attempted = False
    
    try:
        # Create services with zero configuration for network port
        service = DiscoveryService(port=discovery_port)
        auth_manager = AuthManager()
        file_transfer = FileTransfer(service.discovery, auth_manager, network_port=0)
        
        # Create test file on peerB
        if peer_name == "peerB":
            test_file = "test.txt"
            with open(test_file, 'w') as f:
                f.write("This is a test file for peerB")
            print(f"{peer_name}: Created test file: {test_file}")
        
        # Start services
        print(f"{peer_name}: Starting discovery service...")
        await service.start()
        
        # Make sure service name is set now that the discovery service is started
        print(f"{peer_name}: Discovery service name: {service.discovery.service_name}")
        file_transfer.network.service_name = service.discovery.service_name
        
        print(f"{peer_name}: Starting network service...")
        await file_transfer.start()
        print(f"{peer_name}: All services started")
        print(f"{peer_name}: Service Name: {service.discovery.service_name}")
        print(f"{peer_name}: Network Port: {file_transfer.network.port}")
        print(f"{peer_name}: Network Manager Service Name: {file_transfer.network.service_name}")
        
        # Run indefinitely
        print(f"{peer_name}: Running... (Press Ctrl+C to stop)")
        while True:
            await asyncio.sleep(1)
            
            # Only peerA initiates authentication, and only once
            if peer_name == "peerA" and not auth_attempted:
                peers = service.discovery.get_peers()
                if peers:
                    auth_attempted = True
                    for service_name, data in peers.items():
                        try:
                            print(f"\n{peer_name}: Initiating DHE-RSA authentication with {service_name}...")
                            # Request the file using a fixed name
                            success = await file_transfer.request_file(service_name, "test.txt")
                            if success:
                                print(f"✓ DHE-RSA authentication successful with {service_name}")
                                # Show the ephemeral nature - new session key each time
                                session_key = auth_manager.get_session_key(service_name)
                                if session_key:
                                    print(f"  Generated new session key: {session_key.hex()[:16]}...")
                            else:
                                print(f"✗ DHE-RSA authentication failed with {service_name}")
                        except Exception as e:
                            print(f"✗ Error during authentication with {service_name}: {e}")
                            import traceback
                            traceback.print_exc()
            
            # PeerB just shows its verification status when changed
            elif peer_name == "peerB":
                peers = service.discovery.get_peers()
                for service_name, data in peers.items():
                    if auth_manager.is_peer_verified(service_name):
                        session_key = auth_manager.get_session_key(service_name)
                        print(f"\n{peer_name}: Authenticated with {service_name}")
                        print(f"  Using session key: {session_key.hex()[:16]}...")
                        
    except KeyboardInterrupt:
        print(f"\n{peer_name}: Received shutdown signal")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print(f"\n{peer_name}: Shutting down...")
        try:
            if file_transfer:
                await file_transfer.stop()
            if service:
                await service.stop()
        except Exception as e:
            print(f"Error during shutdown: {e}")
        print(f"{peer_name}: Shutdown complete")

async def main():
    if len(sys.argv) != 2:
        print("Usage: python test_peer.py <peer_name>")
        sys.exit(1)
        
    peer_name = sys.argv[1]
    # Each peer uses a different discovery port
    discovery_port = 5000 if peer_name == "peerA" else 5001
    
    await test_peer(peer_name, discovery_port)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nTest terminated by user") 