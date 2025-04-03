#Sends file requests to peers.
#Uses ECDHE-ECDSA-AES256 (AES not yet implemented) (Perfect Forward Secrecy).
#Ensures encrypted files are received securely.
#Now uses a unified transfer_file method for both sending and receiving files.

import asyncio
from typing import List, Tuple
from discovery_service import DiscoveryService
from auth import AuthManager
from network import NetworkManager, input_pending
import os
import json
import base64

class FileTransfer:
    """Handles file transfer operations between peers"""
    
    # Directory for storing files
    FILES_DIR = "Files"
    
    def __init__(self, discovery_service: DiscoveryService, auth_manager: AuthManager, network_port=0):
        """Initialize the file transfer service"""
        self.discovery_service = discovery_service
        self.auth_manager = auth_manager
        
        # Get the underlying discovery instance for internal use
        self.discovery = discovery_service.discovery
        
        # Setup auth manager with discovery information
        self.auth_manager.discovery = self.discovery
        self.auth_manager.service_name = discovery_service.get_service_name()
        self.auth_manager.discovery_service = self.discovery_service
        
        # Setup network manager
        self.network = NetworkManager(port=network_port)
        self.network.auth_manager = auth_manager
        self.network.service_name = discovery_service.get_service_name()
        self.network.discovery = self.discovery  # Set discovery service in network manager
        self.network.discovery_service = self.discovery_service  # Set DiscoveryService reference
        self.network.file_transfer = self  # Set reference to self in network manager
        
        # Ensure Files directory exists
        self.ensure_files_directory()
        
    def ensure_files_directory(self):
        """Ensure the Files directory exists"""
        os.makedirs(self.FILES_DIR, exist_ok=True)
        
    def get_file_path(self, file_name: str) -> str:
        """Get the path to a file in the Files directory"""
        return os.path.join(self.FILES_DIR, file_name)
        
    async def read_file_data(self, file_name: str) -> Tuple[bytes, int]:
        """Read file data from the Files directory
        
        Returns:
            Tuple containing the file content in bytes and the file size
        """
        try:
            file_path = self.get_file_path(file_name)
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File {file_name} not found in Files directory")
                
            with open(file_path, 'rb') as f:
                file_content = f.read()
                
            return file_content, len(file_content)
        except Exception as e:
            print(f"Error reading file {file_name}: {e}")
            raise
            
    async def save_file_data(self, file_name: str, file_content: bytes) -> str:
        """Save file data to the Files directory
        
        Returns:
            The path where the file was saved
        """
        try:
            self.ensure_files_directory()
            file_path = self.get_file_path(file_name)
            
            with open(file_path, 'wb') as f:
                f.write(file_content)
                
            return file_path
        except Exception as e:
            print(f"Error saving file {file_name}: {e}")
            raise
            
    async def transfer_file_data(self, peer_address: str, peer_port: int, file_name: str) -> bool:
        """Low-level method to transfer file data to a peer over a direct TCP connection.
        
        This is an internal utility method that handles the actual data transfer.
        For higher-level file sending with authentication and peer consent, use transfer_file() instead.
        
        Args:
            peer_address: The IP address of the peer
            peer_port: The port of the peer
            file_name: The name of the file to send
            
        Returns:
            True if the file was sent successfully, False otherwise
        """
        try:
            # Read the file data
            file_content, file_size = await self.read_file_data(file_name)
            
            # Create TCP socket and connect to peer
            reader, writer = await asyncio.open_connection(peer_address, peer_port)
            
            try:
                # Prepare file data message
                file_data = {
                    'file_name': os.path.basename(file_name),
                    'file_content': base64.b64encode(file_content).decode('utf-8'),
                    'file_size': file_size
                }
                
                # Send file data
                writer.write(b'D')  # File data message type
                message_data = json.dumps(file_data).encode('utf-8')
                writer.write(len(message_data).to_bytes(4, 'big'))
                writer.write(message_data)
                await writer.drain()
                
                # No need to print here, the caller will handle messaging
                return True
                
            finally:
                writer.close()
                await writer.wait_closed()
                
        except Exception as e:
            print(f"Error sending file data: {e}")
            import traceback
            traceback.print_exc()
            return False

    async def transfer_file(self, peer_name: str, file_name: str, is_sending: bool = True) -> bool:
        """Unified method to transfer files between peers
        
        This method handles both sending and requesting files, using a common workflow:
        1. Looks up peer information from the discovery service
        2. Establishes a secure channel if needed via key exchange
        3. Verifies file existence (for sending) or availability (for requesting)
        4. Gets consent from the peer
        5. Transfers the file data
        
        Args:
            peer_name: The service name of the peer to interact with
            file_name: The name of the file to transfer
            is_sending: True if sending a file to peer, False if requesting a file from peer
            
        Returns:
            True if the file was successfully transferred, False otherwise
        """
        try:
            # Get peer info
            peers = self.discovery_service.get_peers()
            peer_data = peers.get(peer_name)
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
                # Now using the AuthManager's key exchange method
                session_key = await self.auth_manager.initiate_key_exchange(peer_address, peer_port, self.network)
                if not session_key:
                    print(f"Failed to establish secure channel with {peer_name}")
                    return False
                
                # Make sure the session key is now stored
                session_key_check = self.auth_manager.get_session_key(peer_name)
                print(f"After key exchange, is {peer_name} verified: {self.auth_manager.is_peer_verified(peer_name)}")
                print(f"Session key present after exchange: {session_key_check is not None}")
            
            # If sending, check if file exists locally
            if is_sending:
                file_path = self.get_file_path(file_name)
                if not os.path.exists(file_path):
                    print(f"File {file_name} not found in Files directory")
                    return False
                print(f"Requesting to send file {file_name} to {peer_name}")
            else:
                print(f"Requesting file {file_name} from {peer_name}")
            
            # Send file request and wait for consent
            success = await self.network.send_file_request(peer_address, peer_port, file_name, session_key, is_sending=is_sending)
            if not success:
                if is_sending:
                    print(f"File transfer request rejected by {peer_name}")
                else:
                    print(f"Failed to request file {file_name} from {peer_name}")
                return False
                
            if is_sending:
                print(f"File transfer request accepted by {peer_name}")
                # Send the file data
                success = await self.transfer_file_data(peer_address, peer_port, file_name)
                if success:
                    print(f"Successfully sent file {file_name} to {peer_name}")
                else:
                    print(f"Failed to send file to {peer_name}")
            else:
                print(f"Successfully requested file {file_name} from {peer_name}")
                # The file data will be received and processed by the network manager
                
            return success
            
        except Exception as e:
            print(f"Error in transfer_file: {e}")
            import traceback
            traceback.print_exc()
            return False

    async def handle_received_file_data(self, file_data_json: bytes) -> bool:
        """Handle received file data
        
        Args:
            file_data_json: JSON data containing file information
            
        Returns:
            True if the file was successfully processed, False otherwise
        """
        try:
            # Parse the file data
            file_data = json.loads(file_data_json.decode('utf-8'))
            file_name = file_data.get('file_name')
            file_content_b64 = file_data.get('file_content')
            file_size = file_data.get('file_size')
            
            if not file_name or not file_content_b64 or not file_size:
                print(f"Invalid file data received")
                return False
                
            # Decode the file content
            file_content = base64.b64decode(file_content_b64)
            
            # Save the file
            file_path = await self.save_file_data(file_name, file_content)
                
            # Clear, concise message for receiving files
            print(f"\nReceived file {file_name} ({len(file_content)} bytes)")
            print(f"File saved to {file_path}")
            return True
            
        except Exception as e:
            print(f"Error handling received file data: {e}")
            import traceback
            traceback.print_exc()
            return False
        
    async def start(self):
        """Start the file transfer service"""
        await self.network.start()
        
    async def stop(self):
        """Stop the file transfer service"""
        await self.network.stop()
        
    async def update_files(self, files: List[str]):
        """Update the list of available files"""
        await self.discovery_service.update_files(files)

    async def request_user_consent(self, peer_service_name: str, file_name: str, is_receiving: bool = True) -> bool:
        """Ask user for consent for file transfer
        
        Args:
            peer_service_name: The service name of the peer
            file_name: The name of the file to transfer
            is_receiving: True if receiving a file, False if sending a file
            
        Returns:
            True if consent is given, False otherwise
        """
        try:
            # Prepare prompt based on whether receiving or sending
            if is_receiving:
                prompt_msg = f"\nPeer {peer_service_name} wants to send you the file: {file_name}\nDo you want to accept this file? (yes/no): "
            else:
                prompt_msg = f"\nPeer {peer_service_name} wants to request the file: {file_name}\nDo you want to send this file? (yes/no): "
            
            print(prompt_msg, end="", flush=True)
            
            # Set the global flag to indicate we're waiting for input
            global input_pending
            input_pending = True
            
            # Use run_in_executor with an empty prompt since we already printed it
            loop = asyncio.get_event_loop()
            consent = await loop.run_in_executor(None, input)
            
            # Reset the flag since we got input
            input_pending = False
            
            # Add a small delay to prevent the command menu from appearing too quickly
            await asyncio.sleep(1.0)

            # The acceptance or rejection message will be shown by the caller of this function
            return consent.lower() == 'yes'
            
        except Exception as e:
            print(f"Error getting user consent: {e}")
            import traceback
            traceback.print_exc()
            return False
            
    async def send_file_content(self, writer: asyncio.StreamWriter, file_name: str) -> bool:
        """Send file content over a writer
        
        Args:
            writer: The writer to send the file content over
            file_name: The name of the file to send
            
        Returns:
            True if the file was successfully sent, False otherwise
        """
        try:
            # Get file content
            file_content, file_size = await self.read_file_data(file_name)
            
            # Send file content
            file_data = {
                'file_name': os.path.basename(file_name),
                'file_content': base64.b64encode(file_content).decode('utf-8'),
                'file_size': file_size
            }
            
            writer.write(b'D')
            writer.write(len(json.dumps(file_data).encode('utf-8')).to_bytes(4, 'big'))
            writer.write(json.dumps(file_data).encode('utf-8'))
            await writer.drain()
            
            peer_address = writer.get_extra_info('peername')
            # Simplified message that clearly indicates this is in response to a request
            print(f"Sent file {file_name} ({file_size} bytes) to requester")
            return True
            
        except Exception as e:
            print(f"Error sending file content: {e}")
            import traceback
            traceback.print_exc()
            return False
