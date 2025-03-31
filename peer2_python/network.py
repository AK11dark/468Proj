import asyncio
import json
from typing import Optional, Dict, Tuple
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import os
import base64

class NetworkManager:
    def __init__(self, port: int = 5001):
        self.port = port
        self.server = None
        self.connections: Dict[str, asyncio.StreamReader] = {}
        self.auth_manager = None  # Will be set by FileTransfer
        self.service_name = None  # Will be set by FileTransfer
        self.discovery = None  # Will be set by FileTransfer
        
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
        print(f"Incoming connection from {peer_address}")
        try:
            # Read message type and data
            msg_type = await reader.read(1)
            if not msg_type:
                return
                
            print(f"Received message type: {msg_type}")
            data_len = int.from_bytes(await reader.read(4), 'big')
            
            # Validate data length (max 1MB)
            if data_len > 1024 * 1024:
                print(f"Error: Data length {data_len} exceeds maximum allowed size")
                return
                
            print(f"Received {data_len} bytes of data")
            data = await reader.read(data_len)
            
            if len(data) != data_len:
                print(f"Error: Received {len(data)} bytes, expected {data_len}")
                return
            
            # Process message based on type
            if msg_type == b'K':  # Key exchange
                await self._handle_key_exchange(reader, writer, data)
            elif msg_type == b'V':  # Verification challenge
                await self._handle_verification_challenge(reader, writer, data)
            elif msg_type == b'R':  # Verification response
                await self._handle_verification_response(reader, writer, data)
            elif msg_type == b'F':  # File transfer
                await self._handle_file_transfer(reader, writer, data)
            elif msg_type == b'M':  # Mutual authentication
                await self._handle_mutual_authentication(reader, writer, data)
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
                print(f"Connection closed with {peer_address}")
            except Exception as e:
                print(f"Error closing connection with {peer_address}: {e}")
            
    async def _handle_key_exchange(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, data: bytes):
        """Handle key exchange request"""
        peer_address = writer.get_extra_info('peername')
        try:
            # Step 1: Initial ECDSA key exchange
            peer_ecdsa_public_key = data  # Store ECDSA public key
            print(f"Received ECDSA public key from {peer_address}")
            
            # Send our ECDSA public key
            our_public_key = self.auth_manager.get_public_key_bytes()
            print(f"Sending our ECDSA public key ({len(our_public_key)} bytes)")
            writer.write(b'K')  # Key exchange response
            writer.write(len(our_public_key).to_bytes(4, 'big'))
            writer.write(our_public_key)
            await writer.drain()
            
            # Step 2: ECDH Key Exchange
            # Generate ephemeral ECDH key pair
            private_key = ec.generate_private_key(
                curve=ec.SECP256R1(),
                backend=default_backend()
            )
            public_key = private_key.public_key()
            
            # Send our ECDH public key
            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            print(f"Generated ephemeral ECDH key pair")
            
            # Sign our ECDH public key
            ecdh_signature = self.auth_manager.sign_dh_params(public_key_bytes)
            print(f"Signed ECDH public key with ECDSA")
            
            # Send ECDH public key and signature
            print(f"Sending ECDH public key ({len(public_key_bytes)} bytes) and signature ({len(ecdh_signature)} bytes)")
            writer.write(b'D')  # ECDH key
            writer.write(len(public_key_bytes).to_bytes(4, 'big'))
            writer.write(public_key_bytes)
            writer.write(len(ecdh_signature).to_bytes(4, 'big'))
            writer.write(ecdh_signature)
            await writer.drain()
            
            # Receive peer's ECDH value and signature
            print("Waiting for peer's ECDH key and signature...")
            msg_type = await reader.read(1)
            if msg_type != b'D':
                print(f"Invalid ECDH response type from {peer_address}: {msg_type}")
                return
                
            ecdh_len = int.from_bytes(await reader.read(4), 'big')
            peer_ecdh_value = await reader.read(ecdh_len)
            sig_len = int.from_bytes(await reader.read(4), 'big')
            peer_signature = await reader.read(sig_len)
            print(f"Received peer's ECDH key ({ecdh_len} bytes) and signature ({sig_len} bytes)")
            
            # Verify peer's ECDH value signature using their ECDSA key
            if not self.auth_manager.verify_dh_params(peer_ecdh_value, peer_signature, peer_ecdsa_public_key):
                print(f"Failed to verify peer's ECDH parameters")
                return
            
            # Generate shared secret using ECDH
            try:
                peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                    curve=ec.SECP256R1(),
                    data=peer_ecdh_value
                )
                shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
                print(f"Generated shared secret ({len(shared_secret)} bytes)")
            except Exception as e:
                print(f"Error during ECDH key exchange: {e}")
                return
            
            # Derive session key using HKDF
            session_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'file_transfer',
                backend=default_backend()
            ).derive(shared_secret)
            print(f"Derived session key ({len(session_key)} bytes)")
            
            # Find the peer's service name from the discovery service
            peer_service_name = None
            for service_name, data in self.discovery.get_peers().items():
                # Match by IP address only, ignore port since the connection might be from an ephemeral port
                if data['address'] == peer_address[0]:
                    peer_service_name = service_name
                    break
            
            # Debug output to help trace the issue
            print(f"DEBUG - Responder's service name: {self.service_name}")
            print(f"DEBUG - Found peer service name: {peer_service_name}")
            print(f"DEBUG - Discovered peers: {list(self.discovery.get_peers().keys())}")
            
            if peer_service_name:
                # Add peer to verified peers using service name and ECDSA public key
                self.auth_manager.add_verified_peer(peer_service_name, peer_ecdsa_public_key, session_key)
                print(f"Successfully established secure channel with {peer_address}")
                
                # If service_name is None, try to get it now
                if self.service_name is None and self.discovery:
                    self.service_name = self.discovery.service_name
                    print(f"Updated service name to: {self.service_name}")
                
                # Step 3: Send our service name for mutual authentication
                if self.service_name:
                    print(f"Sending mutual authentication with service name: {self.service_name}")
                    try:
                        writer.write(b'M')  # Mutual authentication
                        service_name_bytes = self.service_name.encode('utf-8')
                        writer.write(len(service_name_bytes).to_bytes(4, 'big'))
                        writer.write(service_name_bytes)
                        await writer.drain()
                        print("Mutual authentication message sent successfully")
                        
                        # Keep the connection open a bit longer to allow the peer to process
                        await asyncio.sleep(1.0)
                    except Exception as e:
                        print(f"Error sending mutual authentication: {e}")
                else:
                    print("ERROR: Could not send mutual authentication - service_name is not set")
                
                return session_key
            else:
                print(f"Could not find service name for peer {peer_address}")
                return None
            
        except Exception as e:
            print(f"Error handling key exchange with {peer_address}: {e}")
            import traceback
            traceback.print_exc()
        finally:
            try:
                writer.close()
                await writer.wait_closed()
                print(f"Connection closed with {peer_address}")
            except Exception as e:
                print(f"Error closing connection with {peer_address}: {e}")
            
    async def _handle_verification_challenge(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, data: bytes):
        """Handle verification challenge from peer"""
        try:
            challenge = data
            
            # Sign the challenge
            response = self.auth_manager.sign_challenge(challenge)
            
            # Send response back
            writer.write(b'R')  # Verification response
            writer.write(len(response).to_bytes(4, 'big'))
            writer.write(response)
            await writer.drain()
            
        except Exception as e:
            print(f"Error handling verification challenge: {e}")
            
    async def _handle_verification_response(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, data: bytes):
        """Handle verification response from peer"""
        try:
            response = data
            
            # Verify the response
            is_valid = self.auth_manager.verify_challenge_response(self.service_name, response, self.auth_manager.get_public_key_bytes())
            
            if is_valid:
                print(f"Successfully verified peer {self.service_name}")
            else:
                print(f"Failed to verify peer {self.service_name}")
                
        except Exception as e:
            print(f"Error handling verification response: {e}")
            
    async def initiate_key_exchange(self, peer_address: str, peer_port: int) -> Optional[bytes]:
        """Initiate key exchange with a peer"""
        try:
            # If service_name is None, try to get it now
            if self.service_name is None and self.discovery:
                self.service_name = self.discovery.service_name
                print(f"Updated initiator service name to: {self.service_name}")
                
            reader, writer = await asyncio.open_connection(peer_address, peer_port)
            peer_addr = writer.get_extra_info('peername')
            print(f"Connected to peer at {peer_addr}")
            
            try:
                # Step 1: Send our ECDSA public key
                our_public_key = self.auth_manager.get_public_key_bytes()
                print(f"Sending our ECDSA public key ({len(our_public_key)} bytes)")
                writer.write(b'K')  # Key exchange
                writer.write(len(our_public_key).to_bytes(4, 'big'))
                writer.write(our_public_key)
                await writer.drain()
                
                # Wait for peer's ECDSA public key
                response_type = await reader.read(1)
                if response_type != b'K':
                    print(f"Invalid response type during key exchange: {response_type}")
                    return None
                    
                response_len = int.from_bytes(await reader.read(4), 'big')
                peer_ecdsa_public_key = await reader.read(response_len)
                print("Received peer's ECDSA public key")
                
                # Generate our ephemeral ECDH key pair
                private_key = ec.generate_private_key(
                    curve=ec.SECP256R1(),
                    backend=default_backend()
                )
                public_key = private_key.public_key()
                
                # Send our ECDH public key
                public_key_bytes = public_key.public_bytes(
                    encoding=serialization.Encoding.X962,
                    format=serialization.PublicFormat.UncompressedPoint
                )
                print(f"Generated ephemeral ECDH key pair")
                
                # Sign our ECDH public key
                ecdh_signature = self.auth_manager.sign_dh_params(public_key_bytes)
                print(f"Signed ECDH public key with ECDSA")
                
                # Send ECDH public key and signature
                print(f"Sending ECDH public key ({len(public_key_bytes)} bytes) and signature ({len(ecdh_signature)} bytes)")
                writer.write(b'D')  # ECDH key
                writer.write(len(public_key_bytes).to_bytes(4, 'big'))
                writer.write(public_key_bytes)
                writer.write(len(ecdh_signature).to_bytes(4, 'big'))
                writer.write(ecdh_signature)
                await writer.drain()
                
                # Receive peer's ECDH value and signature
                print("Waiting for peer's ECDH key and signature...")
                msg_type = await reader.read(1)
                if msg_type != b'D':
                    print(f"Invalid ECDH response type: {msg_type}")
                    return None
                    
                ecdh_len = int.from_bytes(await reader.read(4), 'big')
                peer_ecdh_value = await reader.read(ecdh_len)
                sig_len = int.from_bytes(await reader.read(4), 'big')
                peer_signature = await reader.read(sig_len)
                print(f"Received peer's ECDH key ({ecdh_len} bytes) and signature ({sig_len} bytes)")
                
                # Verify peer's ECDH value signature
                if not self.auth_manager.verify_dh_params(peer_ecdh_value, peer_signature, peer_ecdsa_public_key):
                    print("Failed to verify peer's ECDH parameters")
                    return None
                
                # Generate shared secret using ECDH
                try:
                    peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                        curve=ec.SECP256R1(),
                        data=peer_ecdh_value
                    )
                    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
                    print(f"Generated shared secret ({len(shared_secret)} bytes)")
                except Exception as e:
                    print(f"Error during ECDH key exchange: {e}")
                    return None
                
                # Derive session key using HKDF
                session_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b'file_transfer',
                    backend=default_backend()
                ).derive(shared_secret)
                print(f"Derived session key ({len(session_key)} bytes)")
                
                # Debug output
                print(f"DEBUG - Initiator's service name: {self.service_name}")
                print(f"DEBUG - Connecting to peer at: {peer_address}:{peer_port}")
                print(f"DEBUG - Discovered peers: {list(self.discovery.get_peers().keys())}")
                
                # Try to find the peer's service name based on address and port
                known_peer_name = None
                for service_name, data in self.discovery.get_peers().items():
                    # Match by IP address only, since we might connect to an ephemeral port
                    if data['address'] == peer_address:
                        known_peer_name = service_name
                        break
                
                print(f"DEBUG - Found peer service name from discovery: {known_peer_name}")
                
                # Step 3: Send our service name for mutual authentication
                if self.service_name:
                    print(f"Sending mutual authentication with service name: {self.service_name}")
                    try:
                        writer.write(b'M')  # Mutual authentication
                        service_name_bytes = self.service_name.encode('utf-8')
                        writer.write(len(service_name_bytes).to_bytes(4, 'big'))
                        writer.write(service_name_bytes)
                        await writer.drain()
                        print("Mutual authentication message sent successfully")
                        
                        # Keep the connection open a bit longer to allow the peer to process
                        await asyncio.sleep(1.0)
                    except Exception as e:
                        print(f"Error sending mutual authentication: {e}")
                else:
                    print("ERROR: Could not send mutual authentication - service_name is not set")
                
                if known_peer_name:
                    # Add peer to verified peers using discovered service name
                    self.auth_manager.add_verified_peer(known_peer_name, peer_ecdsa_public_key, session_key)
                    print(f"Successfully established secure channel with {known_peer_name}")
                    return session_key
                
                print(f"Could not find service name for peer at {peer_address}:{peer_port}")
                return session_key  # Still return the session key even if we couldn't find the service name
                
            finally:
                writer.close()
                await writer.wait_closed()
                
        except Exception as e:
            print(f"Error initiating key exchange: {e}")
            import traceback
            traceback.print_exc()
            return None
            
    async def send_verification_challenge(self, peer_address: str, peer_port: int, challenge: bytes) -> bool:
        """Send verification challenge to peer"""
        try:
            reader, writer = await asyncio.open_connection(peer_address, peer_port)
            
            # Send message type and challenge
            writer.write(b'V')  # Verification challenge
            writer.write(len(challenge).to_bytes(4, 'big'))
            writer.write(challenge)
            await writer.drain()
            
            # Wait for response
            response_type = await reader.read(1)
            if response_type != b'R':
                return False
                
            response_len = int.from_bytes(await reader.read(4), 'big')
            response = await reader.read(response_len)
            
            writer.close()
            await writer.wait_closed()
            
            return True
            
        except Exception as e:
            print(f"Error sending verification challenge: {e}")
            return False
            
    async def send_file_request(self, peer_address: str, peer_port: int, file_name: str, session_key: bytes) -> bool:
        """Send file request to peer"""
        try:
            if not session_key:
                print(f"No valid session key for peer at {peer_address}:{peer_port}")
                return False
                
            print(f"Sending file request for '{file_name}' to {peer_address}:{peer_port}")
            print(f"Using session key: {session_key.hex()[:16]}...")
                
            # Try to connect to the peer
            try:
                reader, writer = await asyncio.open_connection(peer_address, peer_port)
                print(f"Connected to peer at {peer_address}:{peer_port}")
            except ConnectionRefusedError:
                # If we can't connect to the specified port, try to find the peer by IP only
                service_name = None
                network_port = None
                
                for name, data in self.discovery.get_peers().items():
                    if data['address'] == peer_address:
                        service_name = name
                        network_port = data['port']
                        break
                
                if network_port and network_port != peer_port:
                    print(f"Connection refused on port {peer_port}, trying alternate port {network_port}")
                    reader, writer = await asyncio.open_connection(peer_address, network_port)
                    print(f"Connected to peer at {peer_address}:{network_port}")
                else:
                    raise
            
            # Send file request
            request = {
                "file_name": file_name,
                "session_key": session_key.hex()
            }
            request_data = json.dumps(request).encode('utf-8')
            
            print(f"Sending file request message ({len(request_data)} bytes)")
            writer.write(b'F')  # File transfer
            writer.write(len(request_data).to_bytes(4, 'big'))
            writer.write(request_data)
            await writer.drain()
            
            # Wait for response
            print("Waiting for response...")
            response_type = await reader.read(1)
            if response_type != b'F':
                print(f"Invalid response type for file request: {response_type}")
                return False
                
            response_len = int.from_bytes(await reader.read(4), 'big')
            print(f"Receiving response of {response_len} bytes")
            response_data = await reader.read(response_len)
            response = json.loads(response_data.decode('utf-8'))
            
            if response['status'] == 'ok':
                # Ensure directory exists
                os.makedirs("Files", exist_ok=True)
                
                # Save the file
                file_content = base64.b64decode(response['file_content'])
                file_path = os.path.join("Files", f"received_{file_name}")
                with open(file_path, 'wb') as f:
                    f.write(file_content)
                print(f"Successfully received file {file_name} ({len(file_content)} bytes)")
                print(f"Saved to {file_path}")
            else:
                print(f"Failed to receive file: {response['message']}")
            
            writer.close()
            await writer.wait_closed()
            
            return response['status'] == 'ok'
            
        except Exception as e:
            print(f"Error sending file request: {e}")
            import traceback
            traceback.print_exc()
            return False
            
    async def establish_secure_channel(self, peer_public_key: bytes) -> Optional[bytes]:
        """Establish a secure channel using ECDH"""
        try:
            # Generate ECDH parameters
            parameters = ec.generate_parameters(curve=ec.SECP256R1(), backend=default_backend())
            
            # Generate private key
            private_key = parameters.generate_private_key()
            public_key = private_key.public_key()
            
            # Derive shared secret
            shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
            
            # Derive session key using HKDF
            session_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'file_transfer',
                backend=default_backend()
            ).derive(shared_secret)
            
            return session_key
            
        except Exception as e:
            print(f"Error establishing secure channel: {e}")
            return None
            
    async def _handle_file_transfer(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, data: bytes):
        """Handle file transfer request"""
        peer_address = writer.get_extra_info('peername')
        try:
            print(f"Received file request from {peer_address}")
            # Parse file request
            request_data = json.loads(data.decode('utf-8'))
            file_name = request_data.get('file_name')
            session_key_hex = request_data.get('session_key')
            
            print(f"File requested: {file_name}")
            
            # Check if this is a file request or a file being sent
            if 'file_content' in request_data:
                # This is a file being sent to us
                print(f"Receiving file {file_name} from {peer_address}")
                file_content_b64 = request_data.get('file_content')
                file_size = request_data.get('file_size')
                
                if not file_name or not file_content_b64:
                    print("Invalid file transfer: missing file name or content")
                    response = {
                        'status': 'error',
                        'message': 'Invalid file transfer request'
                    }
                else:
                    # Ensure Files directory exists
                    os.makedirs("Files", exist_ok=True)
                    
                    # Save the file
                    file_content = base64.b64decode(file_content_b64)
                    file_path = os.path.join("Files", f"received_{file_name}")
                    with open(file_path, 'wb') as f:
                        f.write(file_content)
                    
                    print(f"Received file {file_name} ({len(file_content)} bytes)")
                    print(f"Saved to {file_path}")
                    
                    response = {
                        'status': 'ok',
                        'message': f'File {file_name} received successfully'
                    }
            else:
                # This is a file request
                if not file_name or not session_key_hex:
                    print("Invalid file request: missing file name or session key")
                    response = {
                        'status': 'error',
                        'message': 'Invalid file request'
                    }
                    writer.write(b'F')  # File response
                    response_data = json.dumps(response).encode('utf-8')
                    writer.write(len(response_data).to_bytes(4, 'big'))
                    writer.write(response_data)
                    await writer.drain()
                    return
                    
                # Convert session key from hex to bytes
                session_key = bytes.fromhex(session_key_hex)
                print(f"Session key received: {session_key.hex()[:16]}...")
                
                # Check if file exists in Files directory first, then check current directory
                found = False
                file_paths = [
                    os.path.join("Files", file_name),
                    file_name
                ]
                
                print(f"Searching for file in: {file_paths}")
                
                for file_path in file_paths:
                    if os.path.exists(file_path):
                        found = True
                        print(f"File found at: {file_path}")
                        # Read file content
                        with open(file_path, 'rb') as f:
                            file_content = f.read()
                        
                        print(f"File size: {len(file_content)} bytes")
                        # TODO: Encrypt file content with session key
                        # For now, just send the raw content
                        response = {
                            'status': 'ok',
                            'message': f'File {file_name} found at {file_path}',
                            'file_size': len(file_content),
                            'file_content': base64.b64encode(file_content).decode('utf-8')
                        }
                        break
                        
                if not found:
                    print(f"File not found: {file_name}")
                    response = {
                        'status': 'error',
                        'message': f'File {file_name} not found'
                    }
            
            # Send response
            response_data = json.dumps(response).encode('utf-8')
            print(f"Sending response ({len(response_data)} bytes) with status: {response['status']}")
            
            writer.write(b'F')  # File response
            writer.write(len(response_data).to_bytes(4, 'big'))
            writer.write(response_data)
            await writer.drain()
            
        except Exception as e:
            print(f"Error handling file transfer: {e}")
            import traceback
            traceback.print_exc()
            
            try:
                # Send error response
                response = {
                    'status': 'error',
                    'message': f'Internal error: {str(e)}'
                }
                response_data = json.dumps(response).encode('utf-8')
                writer.write(b'F')
                writer.write(len(response_data).to_bytes(4, 'big'))
                writer.write(response_data)
                await writer.drain()
            except:
                pass

    async def _handle_mutual_authentication(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, data: bytes):
        """Handle mutual authentication request"""
        peer_address = writer.get_extra_info('peername')
        try:
            # Decode the peer's service name
            peer_service_name = data.decode('utf-8')
            print(f"Received mutual authentication from {peer_address} with service name: {peer_service_name}")
            
            # Check if the peer exists in our discovery service
            peers = self.discovery.get_peers()
            if peer_service_name in peers:
                # Verify this is actually coming from the right address
                peer_info = peers[peer_service_name]
                expected_address = peer_info['address']
                actual_address = peer_address[0]
                
                if expected_address == actual_address:
                    # We consider this authenticated
                    print(f"Verified identity of peer {peer_service_name}")
                else:
                    print(f"Address mismatch for peer {peer_service_name}: expected {expected_address}, got {actual_address}")
            else:
                print(f"Unknown peer service name: {peer_service_name}")
                
        except Exception as e:
            print(f"Error handling mutual authentication: {e}")
            import traceback
            traceback.print_exc() 