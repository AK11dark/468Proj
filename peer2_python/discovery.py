#Uses mDNS to find and list nearby peers.
#Handles peer announcements and listens for file availability updates.
#test case
# Terminal 1:
# > python main.py
# (Wait for startup)
# Enter command (1-3): 2
# Enter comma-separated list of files to share: test1.txt, test2.txt

# Terminal 2:
# > python main.py
# (Wait for startup)
# Enter command (1-3): 1
# (Should see Terminal 1's peer info and shared files)

from zeroconf import ServiceInfo, Zeroconf, ServiceListener
from zeroconf.asyncio import AsyncZeroconf
import socket
import asyncio
import json
import uuid
from typing import Dict, List, Callable, Optional, Awaitable

class PeerServiceListener(ServiceListener):
    def __init__(self, peer_discovery):
        self.peer_discovery = peer_discovery

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        # Don't handle our own service
        if name != self.peer_discovery.service_name:
            asyncio.create_task(self.peer_discovery._handle_new_peer(name))

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        if name != self.peer_discovery.service_name:
            self.peer_discovery._handle_peer_remove(name)

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        if name != self.peer_discovery.service_name:
            asyncio.create_task(self.peer_discovery._handle_new_peer(name))

class PeerDiscovery:
    def __init__(self, port: int = 5000):
        self.zeroconf = AsyncZeroconf()
        self.port = port
        self.peers: Dict[str, dict] = {}
        self.on_peer_update: Optional[Callable[[str, dict], Awaitable[None]]] = None
        self.service_info = None
        self.pending_files = []
        self.service_listener = PeerServiceListener(self)
        # Generate a unique service name
        self.service_name = f"{socket.gethostname()}-{str(uuid.uuid4())[:8]}._peer2._tcp.local."
        
    async def start(self):
        """Start the peer discovery service"""
        # Create service info for this peer
        self.service_info = ServiceInfo(
            "_peer2._tcp.local.",
            self.service_name,
            addresses=[socket.inet_aton(socket.gethostbyname(socket.gethostname()))],
            port=self.port,
            properties={
                b"files": json.dumps(self.pending_files).encode('utf-8')  # List of available files
            }
        )
        
        # Register our service
        await self.zeroconf.async_register_service(self.service_info)
        
        # Start browsing for other peers
        self.browser = await self.zeroconf.async_add_service_listener(
            "_peer2._tcp.local.",
            self.service_listener
        )
        
    async def stop(self):
        """Stop the peer discovery service"""
        if hasattr(self, 'browser'):
            await self.zeroconf.async_remove_service_listener(self.browser)
        if self.service_info:
            await self.zeroconf.async_unregister_service(self.service_info)
        await self.zeroconf.aclose()
        
    async def _handle_new_peer(self, name: str):
        """Handle discovery of a new peer"""
        info = await self.zeroconf.async_get_service_info("_peer2._tcp.local.", name)
        if info:
            peer_data = {
                "address": socket.inet_ntoa(info.addresses[0]),
                "port": info.port,
                "files": json.loads(info.properties[b"files"].decode('utf-8'))
            }
            self.peers[name] = peer_data
            if self.on_peer_update:
                await self.on_peer_update(name, peer_data)
                
    def _handle_peer_remove(self, name):
        """Handle removal of a peer"""
        if name in self.peers:
            del self.peers[name]
            if self.on_peer_update:
                asyncio.create_task(self.on_peer_update(name, None))  # None indicates peer removal
                
    def update_files(self, files: List[str]):
        """Update the list of files this peer has available"""
        self.pending_files = files
        if self.service_info:
            self.service_info.properties[b"files"] = json.dumps(files).encode('utf-8')
            asyncio.create_task(self.zeroconf.async_update_service(self.service_info))
        
    def get_peers(self) -> Dict[str, dict]:
        """Get the current list of discovered peers"""
        return self.peers.copy()
        
    def set_peer_update_callback(self, callback: Callable[[str, dict], Awaitable[None]]):
        """Set a callback function to be called when peers are added, updated, or removed"""
        self.on_peer_update = callback
