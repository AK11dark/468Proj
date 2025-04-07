# auth_handler.py
import json
import base64
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

KNOWN_PEERS_PATH = "known_peers.json"

def load_known_peers():
    if os.path.exists(KNOWN_PEERS_PATH):
        with open(KNOWN_PEERS_PATH, "r") as f:
            return json.load(f)
    return {}

def save_known_peer(username, public_key_pem):
    peers = load_known_peers()
    peers[username] = public_key_pem
    with open(KNOWN_PEERS_PATH, "w") as f:
        json.dump(peers, f, indent=2)
        
def verify_identity(client_socket, session_key):
    length = int.from_bytes(client_socket.recv(4), 'big')
    payload = client_socket.recv(length)
    data = json.loads(payload.decode("utf-8"))

    username = data["username"]
    pubkey_pem = data["public_key"]
    signature = base64.b64decode(data["signature"])

    # Load claimed public key
    claimed_key = serialization.load_pem_public_key(pubkey_pem.encode())

    # Load known key for this username
    known_peers = load_known_peers()

    if username not in known_peers:
        print(f"👋 First-time peer: {username}")
        print(f"Public key:\n{pubkey_pem}")

        # Trust on first use: save the key
        known_peers[username] = pubkey_pem
        with open(KNOWN_PEERS_PATH, "w") as f:
            json.dump(known_peers, f, indent=2)

        print(f"✅ {username} added to known peers.")
        client_socket.send(b"A")
        return True
        
    expected_pem = known_peers[username]
    expected_key = serialization.load_pem_public_key(expected_pem.encode())

    if expected_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ) != claimed_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ):
        print("❌ Public key mismatch! Possible impersonation.")
        return False

    # Verify signature against session key
    claimed_key.verify(signature, session_key, ec.ECDSA(hashes.SHA256()))

    print(f"✅ Verified identity of peer '{username}'.")
    client_socket.send(b"A")  # Accept
    return True

def handle_migration(data):
    username = data["username"]
    new_key_pem = data["new_key"]
    signature = base64.b64decode(data["signature"])

    known_peers = load_known_peers()

    if username not in known_peers:
        print(f"❌ Cannot process key migration for unknown peer '{username}'.")
        return False

    old_pubkey_pem = known_peers[username]
    old_pubkey = serialization.load_pem_public_key(old_pubkey_pem.encode())

    try:
        old_pubkey.verify(
            signature,
            new_key_pem.encode(),
            ec.ECDSA(hashes.SHA256())
        )
    except Exception as e:
        print(f"❌ Signature verification failed: {e}")
        return False

    known_peers[username] = new_key_pem
    with open(KNOWN_PEERS_PATH, "w") as f:
        json.dump(known_peers, f, indent=2)

    print(f"🔐 Peer '{username}' has rotated their key. New public key stored.")
    return True

