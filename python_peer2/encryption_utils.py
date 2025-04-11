from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
import os
import base64

# The curve that matches Ruby's prime256v1
CURVE = ec.SECP256R1()

def encrypt_file(content, key):
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv)
    ).encryptor()

    ciphertext = encryptor.update(content) + encryptor.finalize()
    tag = encryptor.tag

    return {
        "iv": iv,
        "tag": tag,
        "ciphertext": ciphertext
    }

def generate_key():
    """Generate an EC private key using SECP256R1 (same as Ruby's prime256v1)"""
    return ec.generate_private_key(CURVE)

def public_key_to_pem(private_key):
    """Convert a public key to PEM format, compatible with Ruby's OpenSSL"""
    public_key = private_key.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

def sign(private_key, data):
    """Sign data using EC private key with SHA256, compatible with Ruby's implementation"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))

def verify(public_key, data, signature):
    """Verify signature using public key, compatible with Ruby's implementation"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False
