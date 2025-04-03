import asyncio
import sys
from discovery_service import DiscoveryService

async def test_discovery():
    """Test discovering Ruby peers"""
    print("Starting Python Discovery Client")
    discovery = DiscoveryService(port=5000, auto_print_updates=True)
    
    # Define a callback for discovered peers
    async def handle_peer_update(peer_name, peer_data):
        if peer_data is None:
            print(f"\nPeer {peer_name} left the network")
        else:
            print(f"\nDiscovered peer: {peer_name}")
            print(f"  Address: {peer_data.get('address', 'Unknown')}")
            print(f"  Port: {peer_data.get('port', 'Unknown')}")
            print(f"  Discovery Port: {peer_data.get('discovery_port', 'Unknown')}")
            
            # Print any other properties
            for key, value in peer_data.items():
                if key not in ['address', 'port', 'discovery_port']:
                    print(f"  {key}: {value}")
                    
            # Indicate if this looks like a Ruby client
            if "ruby" in peer_name.lower() or "peer-" in peer_name.lower():
                print(f"  Likely Client Type: {'Ruby' if 'peer-' in peer_name.lower() else 'Python'}")
    
    # Set the callback
    discovery.set_peer_callback(handle_peer_update)
    
    try:
        # Start discovery service
        await discovery.start()
        print(f"Service running as: {discovery.get_service_name()}")
        print("Looking for peers...")
        print("Press Ctrl+C to exit")
        
        # Keep running to collect peer info
        while True:
            await asyncio.sleep(5)
            peers = discovery.get_peers()
            print(f"\nCurrent peers: {len(peers)}")
            # Optionally show all current peers periodically
            if peers:
                for name, data in peers.items():
                    print(f"- {name}: {data.get('address')}:{data.get('port')}")
            
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        await discovery.stop()

if __name__ == "__main__":
    try:
        asyncio.run(test_discovery())
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0) 