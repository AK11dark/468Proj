import asyncio
from discovery import PeerDiscovery
import sys

class DiscoveryService:
    def __init__(self, port: int = 5000):
        self.discovery = PeerDiscovery(port=port)
        self.running = False

    async def handle_peer_update(self, peer_name, peer_data):
        """Handle updates from peers"""
        if peer_data is None:
            print(f"\nPeer {peer_name} left the network")
        else:
            print(f"\nPeer {peer_name} updated:")
            print(f"  Address: {peer_data['address']}:{peer_data['port']}")
            print(f"  Shared files: {peer_data['files']}")

    async def start(self):
        """Start the discovery service"""
        self.discovery.set_peer_update_callback(self.handle_peer_update)
        print("Starting peer discovery service...")
        await self.discovery.start()
        self.running = True

    async def stop(self):
        """Stop the discovery service"""
        if self.running:
            print("Shutting down discovery service...")
            await self.discovery.stop()
            self.running = False

    def update_files(self, files):
        """Update the list of available files"""
        self.discovery.update_files(files)

    async def run(self):
        """Run the discovery service"""
        await self.start()
        try:
            while self.running:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            await self.stop()
            sys.exit(0) 