import os
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import socket

BASE_DIR = Path(__file__).parent.resolve()
KEY_PATH = BASE_DIR / "ecdsa_key.pem"
IDENTITY_PATH = BASE_DIR / "identity.json"

def create_identity():
    # Check if identity already exists
    if KEY_PATH.exists() or IDENTITY_PATH.exists():
        print("❗ Identity already exists. Delete existing files to regenerate.")
        return

    # Generate EC private key
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

    # Extract public key in PEM format
    pubkey = key.public_key()
    pub_pem = pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    # Save identity information
    with open(IDENTITY_PATH, "w") as f:
        json.dump({
            "username": username,
            "public_key": pub_pem
        }, f)
    print(f"👤 Identity saved to {IDENTITY_PATH.name}")

    # Print identity info for sharing
    print("\n👤 Your identity information (share with peers):")
    print(f"Username: {username}")
    print("Public Key:\n" + pub_pem)



def sign_session_key(session_key: bytes):
    # Load private key
    with open(KEY_PATH, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    # Sign the session key
    signature = private_key.sign(session_key, ec.ECDSA(hashes.SHA256()))
    print("🔐 Signing session key...")
    print("🔑 Session Key (hex):", session_key.hex())
    print("✍️ Signature (hex):", signature.hex())

    # Load identity
    with open(IDENTITY_PATH, "r") as f:
        identity = json.load(f)

    # Print public key and username
    print("👤 Username:", identity["username"])
    print("📤 Public Key (PEM):\n" + identity["public_key"])

    return {
        "username": identity["username"],
        "public_key": identity["public_key"],
        "signature": signature.hex()
    }
def send_identity_to_ruby(ip, port, identity_payload):
    print("📤 Sending identity authentication payload to Ruby peer...")

    try:
        with socket.create_connection((ip, port), timeout=5) as sock:
            message = {
                "username": identity_payload["username"],
                "public_key": identity_payload["public_key"],
                "signature": identity_payload["signature"]
            }

            msg_str = json.dumps(message)

            # ✅ First, send the 'A' command byte
            sock.send(b"A")

            # ✅ Then send the JSON payload
            sock.sendall(msg_str.encode())

            print("✅ Authentication payload sent.")
            response = sock.recv(4096).decode().strip()
            return response == "A"

    except Exception as e:
        print("❌ Failed to send identity:", e)

if __name__ == "__main__":
    create_identity()
