from zeroconf import ServiceInfo, Zeroconf, ServiceListener
from zeroconf.asyncio import AsyncZeroconf
import socket
import asyncio
import json
import uuid
from typing import Dict, List, Callable, Optional, Awaitable, Any
from auth import AuthManager
import hashlib

class PeerServiceListener(ServiceListener):
    def __init__(self, peer_discovery):
        self.peer_discovery = peer_discovery

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        # Strictly check this is not our own service
        if name != self.peer_discovery.service_name:
            asyncio.create_task(self.peer_discovery._handle_new_peer(name))

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        if name != self.peer_discovery.service_name:
            asyncio.create_task(self.peer_discovery._handle_peer_remove(name))

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        if name != self.peer_discovery.service_name:
            asyncio.create_task(self.peer_discovery._handle_new_peer(name))

class PeerDiscovery:
    def __init__(self, port: int = 5000, network_port: int = 5001):
        self.port = port
        self.network_port = network_port
        self.zeroconf = None
        self.info = None
        self.service_name = None
        self.peers: Dict[str, Dict[str, Any]] = {}
        self.peer_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None
        self.auth_manager = AuthManager()  # Create AuthManager instance
        
    async def start(self):
        """Start the discovery service"""
        try:
            self.zeroconf = AsyncZeroconf()
            
            # Get local IP address
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Create a unique service name
            self.service_name = f"peer-{uuid.uuid4().hex[:8]}._peer._tcp.local."
            
            # Extract the hostname from the service name (remove _peer._tcp.local. suffix)
            hostname = self.service_name.split("._peer._tcp.local.")[0]
            server = f"{hostname}.local."
            
            # Register our service with both discovery and network ports
            self.info = ServiceInfo(
                "_peer._tcp.local.",
                self.service_name,
                addresses=[socket.inet_aton(local_ip)],
                port=self.port,
                properties={
                    b"address": local_ip.encode('utf-8'),
                    b"discovery_port": str(self.port).encode('utf-8'),
                    b"network_port": str(self.network_port).encode('utf-8')  # Add network port
                },
                server=server  # Add the server parameter
            )
            
            await self.zeroconf.async_register_service(self.info)
            print(f"Discovery service registered on {local_ip}:{self.port}")
            
            # Start browsing for other peers using the listener
            listener = PeerServiceListener(self)
            await self.zeroconf.async_add_service_listener("_peer._tcp.local.", listener)
            
        except Exception as e:
            print(f"Error starting discovery service: {e}")
            raise
            
    async def stop(self):
        """Stop the discovery service"""
        if self.zeroconf:
            await self.zeroconf.async_unregister_service(self.info)
            await self.zeroconf.async_close()
            
    def set_peer_callback(self, callback: Callable[[str, Dict[str, Any]], None]):
        """Set callback for peer updates"""
        self.peer_callback = callback
        
    def get_peers(self) -> Dict[str, Dict[str, Any]]:
        """Get list of discovered peers"""
        # Filter out our own service
        return {name: data for name, data in self.peers.items() if name != self.service_name}
        
    def get_peer_id(self) -> str:
        """Get our peer ID from AuthManager"""
        return self.auth_manager.get_peer_id()

    async def _handle_new_peer(self, name: str):
        """Handle a new peer discovery"""
        try:
            info = await self.zeroconf.async_get_service_info("_peer._tcp.local.", name)
            if info:
                # Only add if not our own service
                if name != self.service_name:
                    # Get network port from service info, fallback to discovery port if not found
                    network_port = int(info.properties.get(b"network_port", info.port))
                    
                    # Create or update peer data
                    peer_data = self.peers.get(name, {})
                    old_files = peer_data.get("files", []) if "files" in peer_data else []
                    
                    # Update connection information
                    peer_data.update({
                        "address": socket.inet_ntoa(info.addresses[0]),
                        "port": network_port,  # Store network port as the main port
                        "discovery_port": info.port  # Store discovery port separately
                    })
                    
                    # Extract files property if available
                    if b"files" in info.properties:
                        try:
                            files_json = info.properties[b"files"].decode('utf-8')
                            new_files = json.loads(files_json)
                            
                            # Silently update files without any announcement
                            peer_data["files"] = new_files
                        except Exception as e:
                            print(f"Error parsing files from peer {name}: {e}")
                    
                    # Store the updated peer information
                    self.peers[name] = peer_data
                    
                    if self.peer_callback:
                        # Handle both sync and async callbacks
                        if asyncio.iscoroutinefunction(self.peer_callback):
                            await self.peer_callback(name, self.peers[name])
                        else:
                            self.peer_callback(name, self.peers[name])
                        
        except Exception as e:
            print(f"Error handling new peer: {e}")

    async def _handle_peer_remove(self, name: str):
        """Handle peer removal"""
        try:
            if name in self.peers and name != self.service_name:
                del self.peers[name]
                if self.peer_callback:
                    # Handle both sync and async callbacks
                    if asyncio.iscoroutinefunction(self.peer_callback):
                        await self.peer_callback(name, None)
                    else:
                        self.peer_callback(name, None)
        except Exception as e:
            print(f"Error handling peer removal: {e}")
                
    async def update_files(self, files: list):
        """Update list of available files"""
        if self.info:
            # Clone the current properties dictionary
            properties = dict(self.info.properties)
            
            # Update the files property
            properties[b"files"] = json.dumps(files).encode('utf-8')
            
            # Get local IP address
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Create a fresh ServiceInfo object
            server = self.info.server
            updated_info = ServiceInfo(
                "_peer._tcp.local.",
                self.service_name,
                addresses=[socket.inet_aton(local_ip)],
                port=self.port,
                properties=properties,
                server=server
            )
            
            # Replace the current service info
            self.info = updated_info
            
            if self.zeroconf:
                try:
                    # Update the service with the new service info
                    await self.zeroconf.async_update_service(updated_info)
                except Exception as e:
                    print(f"Error updating service with files: {e}")

    async def update_service_info(self):
        """Update the service information with the current network port"""
        if not self.zeroconf or not self.info:
            print("Cannot update service info: Zeroconf or service info not initialized")
            return False
            
        try:
            # Get local IP address (if needed)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Get the server name from the original service info
            server = self.info.server
            
            # Preserve all existing properties
            properties = dict(self.info.properties)
            
            # Update with the latest network information
            properties.update({
                b"address": local_ip.encode('utf-8'),
                b"discovery_port": str(self.port).encode('utf-8'),
                b"network_port": str(self.network_port).encode('utf-8')
            })
            
            # Create updated service info with the current network port and preserved properties
            updated_info = ServiceInfo(
                "_peer._tcp.local.",
                self.service_name,
                addresses=[socket.inet_aton(local_ip)],
                port=self.port,
                properties=properties,
                server=server  # Add the server parameter
            )
            
            # Update the service
            await self.zeroconf.async_update_service(updated_info)
            self.info = updated_info
            
            print(f"Updated service info with network port {self.network_port}")
            return True
        except Exception as e:
            print(f"Error updating service info: {e}")
            return False

    async def refresh_peers_info(self):
        """Refresh information for all known peers"""
        for name in list(self.peers.keys()):
            if name != self.service_name:
                try:
                    info = await self.zeroconf.async_get_service_info(
                        "_peer._tcp.local.", 
                        name
                    )
                    if info:
                        # Process the updated peer info
                        await self._handle_new_peer(name)
                except Exception as e:
                    # Silent error handling for peer refresh failures
                    pass
