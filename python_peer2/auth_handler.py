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
        print(f"❌ Rejected: Unknown peer '{username}'.")
        return False

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
