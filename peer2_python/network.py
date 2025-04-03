import asyncio
import json
from typing import Dict, Tuple
import os
import base64
from discovery_service import DiscoveryService

# Global flag to indicate if an input prompt is pending
input_pending = False

class NetworkManager:
    def __init__(self, port: int = 5001):
        self.port = port
        self.server = None
        self.connections: Dict[str, asyncio.StreamReader] = {}
        self.auth_manager = None  # Will be set by FileTransfer
        self.service_name = None  # Will be set by FileTransfer
        self.discovery = None  # Will be set by FileTransfer (PeerDiscovery instance)
        self.discovery_service = None  # Will be set by FileTransfer (DiscoveryService instance)
        self.file_transfer = None  # Will be set by FileTransfer
        
    async def start(self):
        """Start the network server"""
        try:
            # Use port 0 to let the OS choose an available port
            self.server = await asyncio.start_server(
                self._handle_connection,
                '0.0.0.0',
                0 if self.port == 0 else self.port  # Use specified port if non-zero, otherwise let OS choose
            )
            
            # Get the actual port that was assigned
            socket = self.server.sockets[0]
            self.port = socket.getsockname()[1]
            
            print(f"Network server started on port {self.port}")
            
            # Update the network port in the discovery service if available
            if self.discovery:
                self.discovery.network_port = self.port
                # Update the service info with the actual port
                await self.discovery.update_service_info()
                
                # Make sure service_name is updated from discovery service
                self.service_name = self.discovery.service_name
                print(f"Set network manager service name: {self.service_name}")
                
            # Start serving
            await self.server.start_serving()
        except Exception as e:
            print(f"Error starting network server: {e}")
            raise
        
    async def stop(self):
        """Stop the network server"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            print("Network server stopped")
            
    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming connections"""
        peer_address = writer.get_extra_info('peername')
        print(f"\nIncoming connection from {peer_address}")
        try:
            # Read message type and data
            msg_type = await reader.read(1)
            if not msg_type:
                return
                
            # Debug level information, only show for specific message types
            if msg_type not in [b'D', b'F']:  # Don't show for common file operations
                print(f"Received message type: {msg_type}")
                
            data_len = int.from_bytes(await reader.read(4), 'big')
            
            # Validate data length (max 1MB)
            if data_len > 1024 * 1024:
                print(f"Error: Data length {data_len} exceeds maximum allowed size")
                return
                
            # Debug level information, only show for specific message types
            if msg_type not in [b'D', b'F']:  # Don't show for common file operations
                print(f"Received {data_len} bytes of data")
                
            data = await reader.read(data_len)
            
            if len(data) != data_len:
                print(f"Error: Received {len(data)} bytes, expected {data_len}")
                return
            
            # Process message based on type
            if msg_type == b'K':  # Key exchange - delegate to auth manager
                if self.auth_manager:
                    await self.auth_manager.handle_key_exchange(reader, writer, data, self)
                else:
                    print("Error: Auth manager not initialized")
            elif msg_type == b'F':  # File transfer
                await self._handle_file_transfer(reader, writer, data)
            elif msg_type == b'M':  # Mutual authentication - delegate to auth manager
                if self.auth_manager:
                    await self.auth_manager.handle_mutual_authentication(reader, writer, data)
                else:
                    print("Error: Auth manager not initialized")
            elif msg_type == b'D':  # File data transfer - delegate to file transfer
                if self.file_transfer:
                    await self.file_transfer.handle_received_file_data(data)
                else:
                    print("Error: File transfer not initialized")
            else:
                print(f"Unknown message type: {msg_type}")
                
        except Exception as e:
            print(f"Error handling connection from {peer_address}: {e}")
            import traceback
            traceback.print_exc()
        finally:
            try:
                writer.close()
                await writer.wait_closed()
                # Only print for non-file operations to reduce noise
                if msg_type and msg_type not in [b'D', b'F']:
                    print(f"Connection closed with {peer_address}")
            except Exception as e:
                print(f"Error closing connection with {peer_address}: {e}")
    
    async def send_file_request(self, peer_address: str, peer_port: int, file_name: str, session_key: bytes, is_sending: bool = False) -> bool:
        """Send a file request to a peer and wait for consent
        
        Args:
            peer_address: The IP address of the peer
            peer_port: The port of the peer
            file_name: The name of the file to transfer
            session_key: The session key for secure communication
            is_sending: True if sending a file to peer, False if requesting a file from peer
        
        Returns:
            True if the request was accepted, False otherwise
        """
        try:
            # Try to connect to peer
            try:
                reader, writer = await asyncio.open_connection(peer_address, peer_port)
            except ConnectionRefusedError:
                # If connection is refused, try alternate ports
                print(f"Connection refused on port {peer_port}, trying alternate ports...")
                for port in range(peer_port + 1, peer_port + 5):  # Try next 4 ports
                    try:
                        reader, writer = await asyncio.open_connection(peer_address, port)
                        print(f"Connected on alternate port {port}")
                        break
                    except ConnectionRefusedError:
                        continue
                else:
                    print("Could not connect to peer on any port")
                    return False
            
            try:
                # Prepare request data
                request_data = {
                    'file_name': file_name,
                    'session_key': session_key.hex(),
                    'is_sending': is_sending  # Add this flag so the receiver knows if we're sending or requesting
                }
                
                # Send file request
                writer.write(b'F')
                writer.write(len(json.dumps(request_data).encode('utf-8')).to_bytes(4, 'big'))
                writer.write(json.dumps(request_data).encode('utf-8'))
                await writer.drain()
                
                # Wait for consent response
                response_type = await reader.read(1)
                if response_type != b'F':
                    print(f"Invalid response type: {response_type}")
                    return False
                    
                response_len = int.from_bytes(await reader.read(4), 'big')
                response_data = await reader.read(response_len)
                response = json.loads(response_data.decode('utf-8'))
                
                if response.get('status') == 'accepted':
                    return True
                else:
                    if response.get('message'):
                        print(f"Rejection reason: {response.get('message')}")
                    return False
                    
            finally:
                writer.close()
                await writer.wait_closed()
                
        except Exception as e:
            print(f"Error sending file request: {e}")
            import traceback
            traceback.print_exc()
            return False
            
    async def _handle_file_transfer(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, data: bytes):
        """Handle file transfer request"""
        peer_address = writer.get_extra_info('peername')
        try:
            # Parse request data
            request_data = json.loads(data.decode('utf-8'))
            file_name = request_data.get('file_name')
            session_key = request_data.get('session_key')
            is_sending_to_us = request_data.get('is_sending', False)  # Default to False (they're requesting)
            
            if not file_name or not session_key:
                print(f"Invalid file transfer request from {peer_address}")
                return
                
            # Find the peer's service name from the discovery service
            peer_service_name = self.discovery_service.find_peer_by_address(peer_address[0])
            
            if not peer_service_name:
                print(f"Could not find peer service name for {peer_address}")
                return
                
            # Check if peer is verified
            if not self.auth_manager.is_peer_verified(peer_service_name):
                print(f"Peer {peer_service_name} is not verified")
                return
                
            # For a send request, we don't check if file exists locally
            # For a receive request, we do check
            if not is_sending_to_us:
                # They're requesting a file from us, check if it exists
                if self.file_transfer:
                    file_path = self.file_transfer.get_file_path(file_name)
                    if not os.path.exists(file_path):
                        print(f"File {file_name} not found")
                        return
                else:
                    print("Error: File transfer not initialized")
                    return
                
            # Get user consent using the new consent function
            # When is_sending_to_us is True, we're receiving (is_receiving=True)
            # When is_sending_to_us is False, we're sending (is_receiving=False)
            consent = await self.file_transfer.request_user_consent(peer_service_name, file_name, is_receiving=is_sending_to_us)
            
            if not consent:
                # Send rejection response
                response = {'status': 'rejected', 'message': 'User rejected file transfer'}
                writer.write(b'F')
                writer.write(len(json.dumps(response).encode('utf-8')).to_bytes(4, 'big'))
                writer.write(json.dumps(response).encode('utf-8'))
                await writer.drain()
                return
                
            # Send acceptance response
            response = {'status': 'accepted', 'message': 'File transfer accepted'}
            writer.write(b'F')
            writer.write(len(json.dumps(response).encode('utf-8')).to_bytes(4, 'big'))
            writer.write(json.dumps(response).encode('utf-8'))
            await writer.drain()
            
            # If peer is sending us a file, we don't send anything back
            # If peer is requesting a file from us, we send them the file
            if not is_sending_to_us and self.file_transfer:
                await self.file_transfer.send_file_content(writer, file_name)
            else:
                # We're receiving a file, nothing more to do here
                # The file data will be sent separately
                pass
            
        except Exception as e:
            print(f"Error handling file transfer: {e}")
            import traceback
            traceback.print_exc()
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception as e:
                print(f"Error closing connection with {peer_address}: {e}") 