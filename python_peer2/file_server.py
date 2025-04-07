import socket
import json
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from encryption_utils import encrypt_file
from auth_handler import verify_identity



class FileServer:
    def __init__(self, host='0.0.0.0', port=5003):
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.session_key = None  # Dictionary to store session keys per client (IP)

    def start(self):
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        print(f"[Python File Server] Listening on {self.host}:{self.port}...")

        while True: 
            client_socket, client_address = self.server.accept()
            print(f"[Python File Server] Connection from {client_address}")
            self.handle_client(client_socket, client_address)

    def handle_client(self, client_socket, client_address):
        try:
            msg_type = client_socket.recv(1)

            if msg_type == b"F":
                self.handle_file_request(client_socket, client_address)
            elif msg_type == b"K":
                self.handle_key_exchange(client_socket, client_address)
            elif msg_type == b"L":
                self.handle_file_list_request(client_socket)
            elif msg_type == b"A":
                if verify_identity(client_socket, self.session_key):
                    print("✅ Peer authenticated successfully.")
                else:
                    print("❌ Authentication failed.")

            

            else:
                print(f"[Python File Server] ❓ Unknown message type: {msg_type}")

      
        finally:
            client_socket.close()

    def handle_key_exchange(self, client_socket, client_address):
        key_len = int.from_bytes(client_socket.recv(4), 'big')
        payload = client_socket.recv(key_len)
        data = json.loads(payload.decode("utf-8"))

        pem = data.get("public_key").encode()
        peer_public_key = serialization.load_pem_public_key(pem)

        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()

        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
        print(f"[Python] 🔐 Raw shared secret: {shared_key.hex()}")

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'p2p-key-exchange',
        ).derive(shared_key)
        print(f"[Python] 🧪 Final derived key (HKDF): {derived_key.hex()}")

        # Store session key for this client
        self.session_key = derived_key

        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        client_socket.send(len(public_bytes).to_bytes(4, 'big'))
        client_socket.send(public_bytes)
        print("[Python] 📤 Sent PEM public key to Ruby peer")

    def handle_file_request(self, client_socket, client_address):

        data_len = int.from_bytes(client_socket.recv(4), 'big')
        data = client_socket.recv(data_len)
        request = json.loads(data.decode('utf-8'))

        file_name = request.get("file_name")
        print(f"[Python File Server] 📅 Incoming request for file '{file_name}'")

        file_path = os.path.join("Files", file_name)
        if os.path.exists(file_path):
            print(f"📥 File request from {client_address[0]} for '{file_name}'")

       
            confirm = input(f"⚠️ Allow transfer of '{file_name}'? (y/n): ").strip().lower()
     

            if confirm != "y":
                response = {"status": "rejected", "message": "User denied file transfer"}
                client_socket.send(b"F")
                client_socket.send(len(json.dumps(response).encode('utf-8')).to_bytes(4, 'big'))
                client_socket.send(json.dumps(response).encode('utf-8'))
                print("❌ File transfer denied.")
                return

            # Proceed to read + send file
            with open(file_path, 'rb') as file:
                file_content = file.read()

            response = {"status": "accepted"}
            client_socket.send(b"F")
            client_socket.send(len(json.dumps(response).encode('utf-8')).to_bytes(4, 'big'))
            client_socket.send(json.dumps(response).encode('utf-8'))

            encrypted = encrypt_file(file_content, self.session_key)

            client_socket.send(b"D")
            client_socket.send(len(encrypted["iv"]).to_bytes(4, 'big'))
            client_socket.send(encrypted["iv"])
            client_socket.send(len(encrypted["tag"]).to_bytes(4, 'big'))
            client_socket.send(encrypted["tag"])
            client_socket.send(len(encrypted["ciphertext"]).to_bytes(4, 'big'))
            client_socket.send(encrypted["ciphertext"])

            print(f"[Python File Server] ✅ Encrypted file '{file_name}' sent.")

    def handle_file_list_request(self, client_socket):
        try:
            files = os.listdir("Files")
            files = [f for f in files if os.path.isfile(os.path.join("Files", f))]

            response = json.dumps(files).encode('utf-8')
            client_socket.send(b"L")
            client_socket.send(len(response).to_bytes(4, 'big'))
            client_socket.send(response)

            print("[Python File Server] 📃 Sent file list to peer.")
        except Exception as e:
            print(f"[Python File Server] ❌ Error sending file list: {e}")


if __name__ == "__main__":
    server = FileServer()
    server.start()
