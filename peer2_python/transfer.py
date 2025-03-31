#Sends file requests to peers.
#Uses DHE-RSA to derive a unique AES key per transfer (Perfect Forward Secrecy).
#Ensures encrypted files are received securely.

import asyncio
from typing import Optional, List
from discovery import PeerDiscovery
from auth import AuthManager
from network import NetworkManager
import os

class FileTransfer:
    def __init__(self, discovery, auth_manager, network_port=0):
        """Initialize the file transfer service"""
        self.discovery = discovery
        self.auth_manager = auth_manager
        self.network = NetworkManager(port=network_port)
        self.network.auth_manager = auth_manager
        self.network.service_name = discovery.service_name
        self.network.discovery = discovery  # Set discovery service in network manager
        
    async def start(self):
        """Start the file transfer service"""
        await self.network.start()
        
    async def stop(self):
        """Stop the file transfer service"""
        await self.network.stop()
        
    async def request_file(self, service_name: str, file_name: str) -> bool:
        """Request a file from a peer"""
        try:
            # Get peer information from discovery service
            peers = self.discovery.get_peers()
            if service_name not in peers:
                print(f"Peer {service_name} not found in discovery service")
                return False
                
            peer_info = peers[service_name]
            peer_address = peer_info['address']
            peer_port = peer_info['port']  # This should now be the network port from service info
            
            print(f"Connecting to peer at {peer_address}:{peer_port}")
            
            # Check if we already have a secure channel with this peer
            session_key = self.auth_manager.get_session_key(service_name)
            
            # If not, initiate key exchange
            if not session_key:
                print(f"No existing session key for {service_name}, initiating key exchange")
                session_key = await self.network.initiate_key_exchange(peer_address, peer_port)
                if not session_key:
                    print(f"Failed to establish secure channel with {service_name}")
                    return False
                
                # Make sure the session key is now stored
                session_key_check = self.auth_manager.get_session_key(service_name)
                print(f"After key exchange, is {service_name} verified: {self.auth_manager.is_peer_verified(service_name)}")
                print(f"Session key present after exchange: {session_key_check is not None}")
            
            # Send file request
            success = await self.network.send_file_request(peer_address, peer_port, file_name, session_key)
            if success:
                print(f"Successfully requested file {file_name} from {service_name}")
            else:
                print(f"Failed to request file {file_name} from {service_name}")
                
            return success
        except Exception as e:
            print(f"Error requesting file: {e}")
            import traceback
            traceback.print_exc()
            return False
            
    async def send_file(self, peer_name: str, file_name: str) -> bool:
        """Send a file to a peer"""
        try:
            # Get peer info
            peer_data = self.discovery.get_peers().get(peer_name)
            if not peer_data:
                print(f"Peer {peer_name} not found")
                return False
                
            peer_address = peer_data["address"]
            peer_port = peer_data["port"]
            
            print(f"Connecting to peer at {peer_address}:{peer_port}")
            
            # Check if we already have a secure channel with this peer
            session_key = self.auth_manager.get_session_key(peer_name)
            
            # If not, initiate key exchange
            if not session_key:
                print(f"No existing session key for {peer_name}, initiating key exchange")
                session_key = await self.network.initiate_key_exchange(peer_address, peer_port)
                if not session_key:
                    print(f"Failed to establish secure channel with {peer_name}")
                    return False
            
            # Check if file exists
            file_path = file_name
            if not os.path.exists(file_path):
                # Try in Files directory
                file_path = os.path.join("Files", file_name)
                if not os.path.exists(file_path):
                    print(f"File {file_name} not found")
                    return False

            # Read file content
            with open(file_path, 'rb') as f:
                file_content = f.read()
                
            print(f"Read {len(file_content)} bytes from {file_path}")
            
            # Send file directly to peer
            import socket
            import json
            import base64
            
            try:
                # Create TCP socket and connect to peer
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((peer_address, peer_port))
                
                # Prepare file transfer message
                message = {
                    'file_name': os.path.basename(file_name),
                    'file_content': base64.b64encode(file_content).decode('utf-8'),
                    'file_size': len(file_content),
                    'session_key': session_key.hex()
                }
                
                # Send message type 'F' for file transfer
                sock.sendall(b'F')
                
                # Send message length as 4 bytes in big-endian format
                message_data = json.dumps(message).encode('utf-8')
                sock.sendall(len(message_data).to_bytes(4, 'big'))
                
                # Send message data
                sock.sendall(message_data)
                
                # Wait for response
                response_type = sock.recv(1)
                if response_type != b'F':
                    print(f"Invalid response type: {response_type}")
                    sock.close()
                    return False
                    
                # Get response length
                response_len_bytes = sock.recv(4)
                response_len = int.from_bytes(response_len_bytes, 'big')
                
                # Get response data
                response_data = sock.recv(response_len)
                response = json.loads(response_data.decode('utf-8'))
                
                sock.close()
                
                if response.get('status') == 'ok':
                    print(f"File {file_name} sent successfully to {peer_name}")
                    return True
                else:
                    print(f"Failed to send file: {response.get('message', 'Unknown error')}")
                    return False
                
            except Exception as e:
                print(f"Error sending file directly: {e}")
                import traceback
                traceback.print_exc()
                return False
            
        except Exception as e:
            print(f"Error sending file: {e}")
            import traceback
            traceback.print_exc()
            return False
            
    async def update_files(self, files: List[str]):
        """Update the list of available files"""
        await self.discovery.update_files(files)
