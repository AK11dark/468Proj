import asyncio
import os
from discovery_service import DiscoveryService
from transfer import FileTransfer
from auth import AuthManager

async def run_test_scenario():
    """Run a test scenario demonstrating DHE-RSA authentication and file transfer"""
    print("\n=== Starting DHE-RSA Authentication Test Scenario ===\n")
    
    # Create test file
    test_file = "test.txt"
    with open(test_file, 'w') as f:
        f.write("This is a test file for DHE-RSA authentication.")
    print(f"Created test file: {test_file}\n")
    
    # Initialize services
    peer_a_service = None
    peer_b_service = None
    peer_a_transfer = None
    peer_b_transfer = None
    
    try:
        # Start Peer A
        print("Starting Peer A...")
        peer_a_service = DiscoveryService(port=5000)
        peer_a_auth = AuthManager()
        peer_a_transfer = FileTransfer(peer_a_service.discovery, peer_a_auth)
        peer_a_transfer.network.port = 5002
        
        await peer_a_service.start()
        await peer_a_transfer.start()
        print(f"Peer A Service: {peer_a_service.discovery.service_name}")
        print(f"Peer A Network Port: {peer_a_transfer.network.port}\n")
        
        # Start Peer B
        print("Starting Peer B...")
        peer_b_service = DiscoveryService(port=5001)
        peer_b_auth = AuthManager()
        peer_b_transfer = FileTransfer(peer_b_service.discovery, peer_b_auth)
        peer_b_transfer.network.port = 5003
        
        await peer_b_service.start()
        await peer_b_transfer.start()
        print(f"Peer B Service: {peer_b_service.discovery.service_name}")
        print(f"Peer B Network Port: {peer_b_transfer.network.port}\n")
        
        # Wait for peer discovery
        print("Waiting for peer discovery...")
        await asyncio.sleep(2)  # Give time for discovery
        
        # Show discovered peers
        print("\nPeer A's discovered peers:")
        for service_name, data in peer_a_service.discovery.get_peers().items():
            print(f"\nPeer: {service_name}")
            print(f"  Address: {data['address']}")
            print(f"  Authentication Status: {'✓ Verified' if peer_a_auth.is_peer_verified(service_name) else '✗ Not Verified'}")
        
        print("\nPeer B's discovered peers:")
        for service_name, data in peer_b_service.discovery.get_peers().items():
            print(f"\nPeer: {service_name}")
            print(f"  Address: {data['address']}")
            print(f"  Authentication Status: {'✓ Verified' if peer_b_auth.is_peer_verified(service_name) else '✗ Not Verified'}")
        
        # Initiate authentication from Peer A to Peer B
        print("\nInitiating authentication from Peer A to Peer B...")
        peer_b_service_name = list(peer_a_service.discovery.get_peers().keys())[0]
        success = await peer_a_transfer.request_file(peer_b_service_name, test_file)
        
        if success:
            print("✓ Authentication successful!")
            print("\nSession Keys:")
            print(f"Peer A's session key with Peer B: {peer_a_auth.get_session_key(peer_b_service_name).hex()[:16]}...")
            peer_a_service_name = list(peer_b_service.discovery.get_peers().keys())[0]
            print(f"Peer B's session key with Peer A: {peer_b_auth.get_session_key(peer_a_service_name).hex()[:16]}...")
        else:
            print("✗ Authentication failed!")
        
        # Wait a bit to see the results
        await asyncio.sleep(2)
        
    except Exception as e:
        print(f"\nError during test: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("\nCleaning up...")
        if peer_a_transfer:
            await peer_a_transfer.stop()
        if peer_b_transfer:
            await peer_b_transfer.stop()
        if peer_a_service:
            await peer_a_service.stop()
        if peer_b_service:
            await peer_b_service.stop()
        
        # Clean up test file
        if os.path.exists(test_file):
            os.remove(test_file)
            print(f"Removed test file: {test_file}")
        
        print("\nTest completed!")

if __name__ == "__main__":
    try:
        asyncio.run(run_test_scenario())
    except KeyboardInterrupt:
        print("\nTest terminated by user") 