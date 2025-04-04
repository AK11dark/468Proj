import socket
import json
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Function to start the Python file server
def start_file_server(host='0.0.0.0', port=5003):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)

    print(f"[Python File Server] Listening on {host}:{port}...")

    while True:
        client_socket, client_address = server.accept()
        print(f"[Python File Server] Connection from {client_address}")

        try:
            msg_type = client_socket.recv(1)

            if msg_type == b"F":  # File request
                data_len = int.from_bytes(client_socket.recv(4), 'big')
                data = client_socket.recv(data_len)
                request = json.loads(data.decode('utf-8'))

                file_name = request.get("file_name")
                print(f"[Python File Server] 📅 Incoming request for file '{file_name}'")

                file_path = os.path.join("Files", file_name)
                if os.path.exists(file_path):
                    with open(file_path, 'rb') as file:
                        file_content = file.read()

                    response = {"status": "accepted"}
                    client_socket.send(b"F")
                    client_socket.send(len(json.dumps(response).encode('utf-8')).to_bytes(4, 'big'))
                    client_socket.send(json.dumps(response).encode('utf-8'))

                    client_socket.send(b"D")
                    client_socket.send(len(file_content).to_bytes(4, 'big'))
                    client_socket.send(file_content)
                    print(f"[Python File Server] ✅ Sent file '{file_name}'")
                else:
                    response = {"status": "rejected", "message": "File not found"}
                    client_socket.send(b"F")
                    client_socket.send(len(json.dumps(response).encode('utf-8')).to_bytes(4, 'big'))
                    client_socket.send(json.dumps(response).encode('utf-8'))
                    print(f"[Python File Server] ❌ File not found: {file_name}")

            elif msg_type == b"K":  # ECDH Key Exchange (just print for now)
                key_len = int.from_bytes(client_socket.recv(4), 'big')
                payload = client_socket.recv(key_len)
                data = json.loads(payload.decode("utf-8"))

                pem = data.get("public_key").encode()

                peer_public_key = serialization.load_pem_public_key(pem)

                # Step 3: Generate our private key
                private_key = ec.generate_private_key(ec.SECP256R1())
                public_key = private_key.public_key()
 
                # Step 4: Derive shared secret
                shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
                print(f"[Python] 🔐 Raw shared secret: {shared_key.hex()}")

                # Step 5: Derive final key using HKDF (Optional)
                derived_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b'p2p-key-exchange',
                ).derive(shared_key)
                print(f"[Python] 🧪 Final derived key (HKDF): {derived_key.hex()}")
             

                # Step 6: Send our public key back
                public_bytes = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                client_socket.send(len(public_bytes).to_bytes(4, 'big'))
                client_socket.send(public_bytes)
                print("[Python] 📤 Sent PEM public key to Ruby peer")

            else:
                print(f"[Python File Server] ❓ Unknown message type: {msg_type}")

        except Exception as e:
            print(f"[Python File Server] ❌ Error: {e}")
        finally:
            client_socket.close()

# Start server
if __name__ == "__main__":
    start_file_server(host='0.0.0.0', port=5003)
