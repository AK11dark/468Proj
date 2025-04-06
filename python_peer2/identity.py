import os
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

BASE_DIR = Path(__file__).parent.resolve()
KEY_PATH = BASE_DIR / "ecdsa_key.pem"
IDENTITY_PATH = BASE_DIR / "identity.json"

def create_identity():
    # Generate EC key
    key = ec.generate_private_key(ec.SECP256R1())
    with open(KEY_PATH, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"🔐 New ECDSA key saved to {KEY_PATH.name}")

    # Ask for username
    username = input("Enter your username: ").strip()
    with open(IDENTITY_PATH, "w") as f:
        json.dump({ "username": username }, f)
    print(f"👤 Username '{username}' saved to {IDENTITY_PATH.name}")

    # Print public key
    pubkey = key.public_key()
    pub_pem = pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    print("\n👤 Your identity information (share with peers):")
    print(f"Username: {username}")
    print("Public Key:\n" + pub_pem)

if __name__ == "__main__":
    create_identity()
