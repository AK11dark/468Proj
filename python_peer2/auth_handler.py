# auth_handler.py
import json
import base64
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import traceback

KNOWN_PEERS_PATH = "known_peers.json"

def load_known_peers():
    if os.path.exists(KNOWN_PEERS_PATH):
        with open(KNOWN_PEERS_PATH, "r") as f:
            return json.load(f)
    return {}

def save_known_peers(peers):
    with open(KNOWN_PEERS_PATH, "w") as f:
        json.dump(peers, f, indent=2)
        
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
    print("🔍 Received new_key PEM:")
    print(repr(new_key_pem))

    digest = hashes.Hash(hashes.SHA256())
    digest.update(new_key_pem.encode())
    print("🔑 SHA256 of new_key PEM:", digest.finalize().hex())
    if username not in known_peers:
        print(f"❌ Cannot process migration: unknown peer '{username}'")
        return False

    try:
        # Load the old trusted key
        old_key_pem = known_peers[username]
        old_pubkey = serialization.load_pem_public_key(old_key_pem.encode())

        # Verify signature on new public key
        old_pubkey.verify(
            signature,
            new_key_pem.encode(),  # Signatures are over the full PEM string
            ec.ECDSA(hashes.SHA256())
        )

        # If verification passes, update the stored key
        known_peers[username] = new_key_pem
        save_known_peers(known_peers)

        print(f"✅ Key migration verified and updated for peer '{username}'")
        return True

    except Exception as e:
        print(f"❌ Migration verification failed: {e}")
        traceback.print_exc()
        return False

