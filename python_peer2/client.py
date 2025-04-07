# file_request.py
import socket
import json
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def test_ping(ip, port):
    with socket.create_connection((ip, port)) as sock:
        sock.send(b"PING")
        print(f"✅ Sent 'PING' to {ip}:{port}")
def request_file(ip, port, filename, session_key):
    os.makedirs("Received", exist_ok=True)

    with socket.create_connection((ip, port)) as sock:
        # Send file request
        request = { "file_name": filename }
        request_bytes = json.dumps(request).encode("utf-8")
        sock.send(b"F")
        sock.send(len(request_bytes).to_bytes(4, 'big'))
        sock.send(request_bytes)

        # Expect response type "F"
        resp_type = sock.recv(1)
        if resp_type != b"F":
            print("❌ Unexpected response type")
            return

        resp_len = int.from_bytes(sock.recv(4), 'big')
        resp = json.loads(sock.recv(resp_len).decode())

        if resp.get("status") != "accepted":
            print("❌ Rejected:", resp.get("message"))
            return

        # Expect data block
        dtype = sock.recv(1)
        if dtype != b"D":
            print("❌ Expected encrypted file data block, got:", dtype)
            return

        # Read encrypted payload (IV, tag, ciphertext)
        iv_len = int.from_bytes(sock.recv(4), 'big')
        iv = sock.recv(iv_len)

        tag_len = int.from_bytes(sock.recv(4), 'big')
        tag = sock.recv(tag_len)

        ct_len = int.from_bytes(sock.recv(4), 'big')
        ciphertext = sock.recv(ct_len)

        # Decrypt using AES-256-GCM
        try:
            decryptor = Cipher(
                algorithms.AES(session_key),
                modes.GCM(iv, tag)
            ).decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        except Exception as e:
            print("❌ Decryption failed:", e)
            return

        # Save decrypted file
        save_path = f"Received/{filename}"
        with open(save_path, 'wb') as f:
            f.write(plaintext)

        print(f"✅ File '{filename}' decrypted and saved to {save_path}")

def perform_key_exchange_with_ruby(peer_ip, peer_port):
    print("[Python Client] 🧠 Generating EC key pair...")
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Connect to Ruby peer
    sock = socket.create_connection((peer_ip, peer_port))
    sock.send(b"K")  # Initiate key exchange

    payload = json.dumps({
        "public_key": public_bytes.decode()
    }).encode('utf-8')

    sock.send(len(payload).to_bytes(4, 'big'))
    sock.send(payload)
    print(f"[Python Client] 📤 Sent public key to Ruby at {peer_ip}:{peer_port}")

    # Receive Ruby's public key
    resp_len = int.from_bytes(sock.recv(4), 'big')
    resp_data = sock.recv(resp_len)
    ruby_pub_key = serialization.load_pem_public_key(resp_data)
    print("[Python Client] 📥 Received Ruby's public key.")

    # Derive shared secret
    shared_key = private_key.exchange(ec.ECDH(), ruby_pub_key)
    print(f"[Python Client] 🤝 Raw shared secret: {shared_key.hex()}")

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'p2p-key-exchange',
    ).derive(shared_key)

    print(f"[Python Client] 🧪 Derived session key: {derived_key.hex()}")

    sock.close()
    return derived_key