#Uses RSA signatures to sign and verify file metadata.
#Ensures only authorized peers can distribute files.

import hashlib
import hmac
import os
import time
from typing import Dict, Optional, Tuple
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
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