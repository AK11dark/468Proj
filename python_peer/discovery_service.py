import asyncio
from discovery import PeerDiscovery
from typing import Optional, Callable, Dict, Any
import sys

class DiscoveryService:
    def __init__(self, port: int = 5000, auto_print_updates: bool = False):
        self.port = port
        self.discovery = PeerDiscovery(port=port)
        self.peer_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None
        self.running = False
        self.auto_print_updates = auto_print_updates
        
    def set_peer_callback(self, callback: Callable[[str, Dict[str, Any]], None]):
        """Set callback for peer updates"""
        self.peer_callback = callback
        self.discovery.set_peer_callback(callback)
        
    async def handle_peer_update(self, peer_name, peer_data):
        """Handle updates from peers"""
        if not self.auto_print_updates:
            return
            
        if peer_data is None:
            print(f"\nPeer {peer_name} left the network")
        else:
            print(f"\nPeer {peer_name} updated:")
            print(f"  Address: {peer_data['address']}:{peer_data['port']}")
            if 'files' in peer_data:
                print(f"  Shared files: {peer_data['files']}")
            if 'peer_id' in peer_data:
                print(f"  Peer ID: {peer_data['peer_id']}")

    async def start(self):
        """Start the discovery service"""
        print(f"Initializing DiscoveryService on port {self.port}")
        try:
            # Only set automatic update handler if auto_print_updates is enabled
            if self.auto_print_updates:
                self.set_peer_callback(self.handle_peer_update)
            print("Starting peer discovery service...")
            await self.discovery.start()
            self.running = True
            print("Discovery service started successfully")
        except Exception as e:
            print(f"Error starting discovery service: {e}")
            import traceback
            traceback.print_exc()
            raise

    async def stop(self):
        """Stop the discovery service"""
        if self.running:
            try:
                print("Shutting down discovery service...")
                await self.discovery.stop()
                self.running = False
                print("Discovery service stopped successfully")
            except Exception as e:
                print(f"Error stopping discovery service: {e}")
                import traceback
                traceback.print_exc()

    def get_peers(self) -> Dict[str, Dict[str, Any]]:
        """Get list of discovered peers"""
        return self.discovery.get_peers()
        
    def get_service_name(self) -> str:
        """Get the service name of this peer"""
        return self.discovery.service_name
        
    async def update_files(self, files: list):
        """Update list of available files"""
        try:
            await self.discovery.update_files(files)
        except Exception as e:
            print(f"Error updating files: {e}")
            
    async def refresh_peers_info(self):
        """Refresh information for all known peers"""
        try:
            await self.discovery.refresh_peers_info()
        except Exception as e:
            print(f"Error refreshing peer information: {e}")
            import traceback
            traceback.print_exc()
            
    async def update_service_info(self):
        """Update the service information with the current network port"""
        try:
            success = await self.discovery.update_service_info()
            if not success:
                print("Failed to update service information")
            return success
        except Exception as e:
            print(f"Error updating service information: {e}")
            import traceback
            traceback.print_exc()
            return False

    def find_peer_by_address(self, ip_address: str) -> str:
        """Find a peer's service name by IP address
        
        Args:
            ip_address: The IP address to search for
            
        Returns:
            The service name of the peer with the matching IP address, or None if not found
        """
        for service_name, data in self.get_peers().items():
            # Match by IP address only, since port might be different
            if data['address'] == ip_address:
                return service_name
        return None

    async def run(self):
        """Run the discovery service"""
        # Only start if not already running
        if not self.running:
            await self.start()
        try:
            while self.running:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            await self.stop()
            sys.exit(0) 