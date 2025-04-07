import os
import json
from pathlib import Path
from discover import discover_peers
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import socket
import base64

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



def rotate_public_key():
    if not IDENTITY_PATH.exists() or not KEY_PATH.exists():
        print("❌ Cannot rotate key: identity or private key not found.")
        return None

    # Load current identity
    with open(IDENTITY_PATH, "r") as f:
        identity = json.load(f)
    username = identity["username"]
    old_pubkey = identity["public_key"]

    # Load old private key
    with open(KEY_PATH, "rb") as f:
        old_private_key = serialization.load_pem_private_key(f.read(), password=None)

    # Generate new key pair
    new_private_key = ec.generate_private_key(ec.SECP256R1())
    new_public_key = new_private_key.public_key()

    new_pubkey_pem = new_public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    # Sign the new public key with old private key
    signature = old_private_key.sign(
        new_pubkey_pem.encode(),
        ec.ECDSA(hashes.SHA256())
    )

    # Save new private key to file
    with open(KEY_PATH, "wb") as f:
        f.write(new_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save updated identity
    with open(IDENTITY_PATH, "w") as f:
        json.dump({
            "username": username,
            "public_key": new_pubkey_pem
        }, f, indent=2)

    # Build migration message
    migrate_msg = {
        "username": username,
        "new_key": new_pubkey_pem,
        "signature": base64.b64encode(signature).decode()
    }

    print("🔁 Identity key rotated.")
    print("📤 Send this migration message to your peers:")
    print(json.dumps(migrate_msg, indent=2))

    return migrate_msg  # So you can send it automatically if you want

def notify_peers_of_rotation(migrate_msg):
    peers = discover_peers()
    if not peers:
        print("❌ No peers found to notify.")
        return

    print("\nChoose peer(s) to notify:")
    for i, peer in enumerate(peers, 1):
        print(f"{i}. {peer['name']} @ {peer['ip']}:{peer['port']}")
    selected = input("Enter peer numbers separated by commas (or 'a' for all): ").strip()

    if selected.lower() == 'a':
        selected_peers = peers
    else:
        try:
            indexes = [int(i.strip()) - 1 for i in selected.split(',')]
            selected_peers = [peers[i] for i in indexes if 0 <= i < len(peers)]
        except:
            print("❌ Invalid selection.")
            return

    for peer in selected_peers:
        try:
            with socket.create_connection((peer["ip"], peer["port"]), timeout=5) as sock:
                msg_bytes = json.dumps(migrate_msg).encode()
                sock.send(b"M")
                sock.send(len(msg_bytes).to_bytes(4, 'big'))
                sock.sendall(msg_bytes)
                response = sock.recv(1)
                if response == b"M":
                    print(f"✅ {peer['name']} accepted your new key.")
                else:
                    print(f"⚠️ {peer['name']} rejected your key migration.")
        except Exception as e:
            print(f"❌ Failed to notify {peer['name']}: {e}")




if __name__ == "__main__":
    create_identity()
