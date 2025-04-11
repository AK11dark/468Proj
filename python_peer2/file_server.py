import socket
import json
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from encryption_utils import encrypt_file
from auth_handler import verify_identity, handle_migration
from storage import SecureStorage
from getpass import getpass
from auth_handler import handle_migration
import queue
import threading
import time

# Global pending request queue
pending_requests = queue.Queue()
# Flag to indicate if there's a pending request
has_pending_request = threading.Event()

class FileServer:
    def __init__(self, host='0.0.0.0', port=5003):
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.session_key = None  # Dictionary to store session keys per client (IP)
        self.secure_storage = SecureStorage()

    def start(self):
        try:
            self.server.bind((self.host, self.port))
            self.server.listen(5)
            print(f"[Python File Server] Listening on {self.host}:{self.port}...")

            while True: 
                client_socket, client_address = self.server.accept()
                print(f"[Python File Server] Connection from {client_address}")
                self.handle_client(client_socket, client_address)
        except OSError as e:
            if e.errno == 98:  # Address already in use
                print("[Python File Server] Server already running. Continuing with client mode only.")
                return
            else:
                raise  # Re-raise if it's a different error

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
            elif msg_type == b"M":
                length = int.from_bytes(client_socket.recv(4), 'big')
                payload = client_socket.recv(length)
                message = json.loads(payload.decode("utf-8"))

                
                success = handle_migration(message)
                client_socket.send(b"M" if success else b"R")


            

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
            
            # Put request in queue and wait for confirmation from main thread
            req_info = {
                'type': 'file_request',
                'file_name': file_name,
                'file_path': file_path,
                'client_socket': client_socket,
                'client_address': client_address,
                'response': None  # Will be set by the main thread
            }
            
            # Clear any existing event flag first to avoid race conditions
            has_pending_request.clear()
            
            # Ensure queue is empty before adding a new request
            while not pending_requests.empty():
                try:
                    pending_requests.get_nowait()
                except queue.Empty:
                    break
            
            # Now add our request and set the event
            pending_requests.put(req_info)
            has_pending_request.set()
            print("\n" + "=" * 60)
            print(f"🔔 FILE TRANSFER REQUEST: '{file_name}'")
            print(f"→ A confirmation prompt will appear on the main console...")
            print("=" * 60)
            
            # Wait for response with timeout
            start_time = time.time()
            while time.time() - start_time < 60:  # 60 second timeout
                if req_info['response'] is not None:
                    break
                time.sleep(0.1)
            
            # Check response
            if req_info['response'] is None or req_info['response'].lower() != 'y':
                # Timed out or rejected
                response = {"status": "rejected", "message": "User denied file transfer"}
                client_socket.send(b"F")
                client_socket.send(len(json.dumps(response).encode('utf-8')).to_bytes(4, 'big'))
                client_socket.send(json.dumps(response).encode('utf-8'))
                print("❌ File transfer denied.")
                return
            
            # User confirmed, continue with file transfer
            # Check if file is encrypted and needs password
            is_encrypted = file_name.endswith('.enc')
            file_content = None
            
            if is_encrypted:
                print("🔒 This file is encrypted. Enter the password to decrypt it.")
                password = getpass("Enter password: ")
                file_content = self.secure_storage.get_file_content(file_name, password)
                
                if file_content is None:
                    response = {"status": "rejected", "message": "Failed to decrypt file"}
                    client_socket.send(b"F")
                    client_socket.send(len(json.dumps(response).encode('utf-8')).to_bytes(4, 'big'))
                    client_socket.send(json.dumps(response).encode('utf-8'))
                    print("❌ Decryption failed. File transfer aborted.")
                    return
            else:
                # Proceed to read file
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
        else:
            # Check if there's an encrypted version of the file
            encrypted_path = os.path.join("Files", file_name + ".enc")
            if os.path.exists(encrypted_path):
                print(f"📥 Encrypted file request from {client_address[0]} for '{file_name}'")
                
                # Put request in queue and wait for confirmation from main thread
                req_info = {
                    'type': 'encrypted_file_request',
                    'file_name': file_name,
                    'encrypted_path': encrypted_path,
                    'client_socket': client_socket,
                    'client_address': client_address,
                    'response': None  # Will be set by the main thread
                }
                
                # Clear any existing event flag first to avoid race conditions
                has_pending_request.clear()
                
                # Ensure queue is empty before adding a new request
                while not pending_requests.empty():
                    try:
                        pending_requests.get_nowait()
                    except queue.Empty:
                        break
                
                # Now add our request and set the event
                pending_requests.put(req_info)
                has_pending_request.set()
                print("\n" + "=" * 60)
                print(f"🔔 ENCRYPTED FILE TRANSFER REQUEST: '{file_name}'")
                print(f"→ A confirmation prompt will appear on the main console...")
                print("=" * 60)
                
                # Wait for response with timeout
                start_time = time.time()
                while time.time() - start_time < 60:  # 60 second timeout
                    if req_info['response'] is not None:
                        break
                    time.sleep(0.1)
                
                # Check response
                if req_info['response'] is None or req_info['response'].lower() != 'y':
                    # Timed out or rejected
                    response = {"status": "rejected", "message": "User denied file transfer"}
                    client_socket.send(b"F")
                    client_socket.send(len(json.dumps(response).encode('utf-8')).to_bytes(4, 'big'))
                    client_socket.send(json.dumps(response).encode('utf-8'))
                    print("❌ File transfer denied.")
                    return
                
                # User confirmed, continue with file transfer
                print("🔒 This file is encrypted. Enter the password to decrypt it.")
                password = getpass("Enter password: ")
                
                file_content = self.secure_storage.get_file_content(file_name + ".enc", password)
                
                if file_content is None:
                    response = {"status": "rejected", "message": "Failed to decrypt file"}
                    client_socket.send(b"F")
                    client_socket.send(len(json.dumps(response).encode('utf-8')).to_bytes(4, 'big'))
                    client_socket.send(json.dumps(response).encode('utf-8'))
                    print("❌ Decryption failed. File transfer aborted.")
                    return
                    
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

                print(f"[Python File Server] ✅ Decrypted and sent file '{file_name}'.")
            else:
                response = {"status": "rejected", "message": "File not found"}
                client_socket.send(b"F")
                client_socket.send(len(json.dumps(response).encode('utf-8')).to_bytes(4, 'big'))
                client_socket.send(json.dumps(response).encode('utf-8'))
                print(f"❌ File '{file_name}' not found.")

    def handle_file_list_request(self, client_socket):
        try:
            # Get both regular and encrypted files
            files = os.listdir("Files")
            
            # Show encrypted files with their .enc extension removed for clarity
            file_list = []
            for f in files:
                file_path = os.path.join("Files", f)
                if os.path.isfile(file_path):
                    # Calculate SHA-256 hash of the file
                    file_hash = self.calculate_file_hash(file_path)
                    
                    if f.endswith('.enc'):
                        # Add both the encrypted name and the original name
                        original_name = f.rsplit('.enc', 1)[0]
                        file_list.append({"name": f"{original_name} 🔒", "hash": file_hash})
                    else:
                        file_list.append({"name": f, "hash": file_hash})

            response = json.dumps(file_list).encode('utf-8')
            client_socket.send(b"L")
            client_socket.send(len(response).to_bytes(4, 'big'))
            client_socket.send(response)

            print("[Python File Server] 📃 Sent file list with hashes to peer.")
        except Exception as e:
            print(f"[Python File Server] ❌ Error sending file list: {e}")
            
    def calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file"""
        sha256 = hashes.Hash(hashes.SHA256())
        with open(file_path, 'rb') as f:
            # Read file in chunks to handle large files
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.finalize().hex()

# If run directly, start the server
if __name__ == "__main__":
    print("[Python] 📂 Starting file server...")
    server = FileServer()
    server.start()
