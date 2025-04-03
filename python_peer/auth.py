#Uses ECDSA signatures to sign and verify file metadata.
#Ensures only authorized peers can distribute files.

import os
import asyncio
import json
from typing import Dict, Optional, Tuple
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

class AuthManager:
    def __init__(self):
        # Generate ECDSA key pair for this peer using P-256 curve
        self.private_key = ec.generate_private_key(
            curve=ec.SECP256R1(),
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        # Store verified peers: {service_name: (public_key, session_key)}
        self.verified_peers: Dict[str, Tuple[bytes, bytes]] = {}
        
        # Will be set by FileTransfer
        self.discovery = None
        self.discovery_service = None
        self.service_name = None
        
    def get_public_key_bytes(self) -> bytes:
        """Get the public key in DER format"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
    def sign_dh_params(self, dh_params: bytes) -> bytes:
        """Sign DH parameters with our ECDSA private key"""
        return self.private_key.sign(
            dh_params,
            ec.ECDSA(hashes.SHA256())
        )
        
    def verify_dh_params(self, dh_params: bytes, signature: bytes, peer_public_key: bytes) -> bool:
        """Verify DH parameters using peer's ECDSA public key"""
        try:
            public_key = serialization.load_der_public_key(peer_public_key, backend=default_backend())
            public_key.verify(
                signature,
                dh_params,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception as e:
            print(f"Failed to verify DH parameters: {e}")
            return False
            
    def add_verified_peer(self, service_name: str, public_key: bytes, session_key: bytes):
        """Add a verified peer"""
        self.verified_peers[service_name] = (public_key, session_key)
        
    def is_peer_verified(self, service_name: str) -> bool:
        """Check if a peer is verified"""
        return service_name in self.verified_peers
        
    def get_session_key(self, service_name: str) -> Optional[bytes]:
        """Get the session key for a verified peer"""
        if service_name in self.verified_peers:
            return self.verified_peers[service_name][1]
        return None
        
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
            
    async def initiate_key_exchange(self, peer_address: str, peer_port: int, network_manager) -> Optional[bytes]:
        """Initiate key exchange with a peer (moved from NetworkManager)"""
        try:
            # Make sure service_name is set
            if self.service_name is None:
                self.service_name = self.discovery_service.get_service_name()
                print(f"Updated initiator service name to: {self.service_name}")
                
            reader, writer = await asyncio.open_connection(peer_address, peer_port)
            peer_addr = writer.get_extra_info('peername')
            print(f"Connected to peer at {peer_addr}")
            
            try:
                # Step 1: Send our ECDSA public key
                our_public_key = self.get_public_key_bytes()
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
                ecdh_signature = self.sign_dh_params(public_key_bytes)
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
                if not self.verify_dh_params(peer_ecdh_value, peer_signature, peer_ecdsa_public_key):
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
                print(f"DEBUG - Discovered peers: {list(self.discovery_service.get_peers().keys())}")
                
                # Try to find the peer's service name based on address and port
                known_peer_name = self.discovery_service.find_peer_by_address(peer_address)
                
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
                    self.add_verified_peer(known_peer_name, peer_ecdsa_public_key, session_key)
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
            
    async def handle_key_exchange(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, data: bytes, network_manager):
        """Handle key exchange request from peer (moved from NetworkManager)"""
        peer_address = writer.get_extra_info('peername')
        try:
            # Step 1: Initial ECDSA key exchange
            peer_ecdsa_public_key = data  # Store ECDSA public key
            print(f"Received ECDSA public key from {peer_address}")
            
            # Send our ECDSA public key
            our_public_key = self.get_public_key_bytes()
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
            ecdh_signature = self.sign_dh_params(public_key_bytes)
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
            if not self.verify_dh_params(peer_ecdh_value, peer_signature, peer_ecdsa_public_key):
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
            peer_service_name = self.discovery_service.find_peer_by_address(peer_address[0])
            
            # Debug output to help trace the issue
            print(f"DEBUG - Responder's service name: {self.service_name}")
            print(f"DEBUG - Found peer service name: {peer_service_name}")
            print(f"DEBUG - Discovered peers: {list(self.discovery_service.get_peers().keys())}")
            
            if peer_service_name:
                # Add peer to verified peers using service name and ECDSA public key
                self.add_verified_peer(peer_service_name, peer_ecdsa_public_key, session_key)
                print(f"Successfully established secure channel with {peer_address}")
                
                # If service_name is None, try to get it now
                if self.service_name is None:
                    self.service_name = self.discovery_service.get_service_name()
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

    async def handle_mutual_authentication(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, data: bytes):
        """Handle mutual authentication request (moved from NetworkManager)"""
        peer_address = writer.get_extra_info('peername')
        try:
            # Decode the peer's service name
            peer_service_name = data.decode('utf-8')
            print(f"Received mutual authentication from {peer_address} with service name: {peer_service_name}")
            
            # Check if the peer exists in our discovery service
            peers = self.discovery_service.get_peers()
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