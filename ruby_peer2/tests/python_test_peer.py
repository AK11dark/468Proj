#!/usr/bin/env python3
"""
Python Test Peer for Ruby-Python interoperability testing.
This script sets up a minimal Python peer for Ruby tests to connect to.
"""

import socket
import json
import os
import sys
import time
import threading
import argparse
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../python_peer2")))

try:
    # Try importing from the python_peer2 directory
    from encryption_utils import encrypt_file
except ImportError:
    # Define a minimal implementation if the module is not available
    print("Warning: Could not import encryption_utils. Using minimal implementation.")
    
    def encrypt_file(plaintext, key):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        import os
        
        iv = os.urandom(12)  # GCM recommends 12 bytes
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        return {
            "iv": iv,
            "tag": encryptor.tag,
            "ciphertext": ciphertext
        }

# Directory setup
os.makedirs("Files", exist_ok=True)

# Test file
TEST_FILE_NAME = f"python_test_{int(time.time())}.txt"
TEST_FILE_CONTENT = f"This is a test file from Python for Ruby interop testing. {os.urandom(8).hex()}"

# Global session key
session_key = None
auto_accept_requests = False

class TestPeer:
    def __init__(self, host="0.0.0.0", port=5003):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.running = False
    
    def start(self):
        global session_key
        
        # Create test file
        with open(os.path.join("Files", TEST_FILE_NAME), 'w') as f:
            f.write(TEST_FILE_CONTENT)
        print(f"📄 Created test file: {TEST_FILE_NAME}")
        
        # Start server
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.running = True
        
        print(f"🚀 Python test peer started on {self.host}:{self.port}")
        print("Commands: [list] Show available files, [exit] Stop server")
        print("Tests from Ruby should automatically connect to this peer.")
        
        # Start command line thread
        cmd_thread = threading.Thread(target=self.process_commands)
        cmd_thread.daemon = True
        cmd_thread.start()
        
        try:
            while self.running:
                self.server_socket.settimeout(1.0)  # Check every second if we should exit
                try:
                    client_socket, client_address = self.server_socket.accept()
                    print(f"📥 Connection from {client_address[0]}:{client_address[1]}")
                    
                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"Error accepting connection: {e}")
                    
        finally:
            self.server_socket.close()
            print("Server stopped.")
    
    def process_commands(self):
        while self.running:
            try:
                cmd = input("Command> ").strip().lower()
                if cmd == "exit":
                    self.running = False
                    print("Stopping server...")
                    break
                elif cmd == "list":
                    print("\n📂 Files available:")
                    for filename in os.listdir("Files"):
                        print(f"  - {filename}")
                elif cmd == "auto":
                    global auto_accept_requests
                    auto_accept_requests = not auto_accept_requests
                    print(f"Auto-accept requests: {auto_accept_requests}")
                elif cmd == "key":
                    if session_key:
                        print(f"Current session key: {session_key.hex()}")
                    else:
                        print("No session key established yet.")
                else:
                    print("Unknown command. Available commands: list, exit, auto, key")
            except Exception as e:
                print(f"Error processing command: {e}")
    
    def handle_client(self, client_socket, client_address):
        try:
            # Read command (1 byte)
            command = client_socket.recv(1)
            
            if command == b"K":
                self.handle_key_exchange(client_socket, client_address)
            elif command == b"L":
                self.handle_file_list_request(client_socket)
            elif command == b"F":
                self.handle_file_request(client_socket, client_address)
            else:
                print(f"❓ Unknown command: {command}")
        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            client_socket.close()
    
    def handle_key_exchange(self, client_socket, client_address):
        global session_key
        
        try:
            # Read length-prefixed JSON payload
            length = int.from_bytes(client_socket.recv(4), byteorder="big")
            payload = client_socket.recv(length)
            data = json.loads(payload.decode())
            
            # Extract Ruby's public key
            ruby_pem = data["public_key"].encode()
            ruby_pub_key = serialization.load_pem_public_key(ruby_pem)
            print("📥 Received Ruby's public key")
            
            # Generate our EC key pair
            private_key = ec.generate_private_key(ec.SECP256R1())
            public_key = private_key.public_key()
            
            # Derive shared secret
            shared_key = private_key.exchange(ec.ECDH(), ruby_pub_key)
            print(f"🔐 Raw shared secret: {shared_key.hex()}")
            
            # Apply HKDF to derive final key
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'p2p-key-exchange',
            ).derive(shared_key)
            
            print(f"🔑 Derived session key: {derived_key.hex()}")
            session_key = derived_key
            
            # Send our public key back
            public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            client_socket.send(len(public_bytes).to_bytes(4, byteorder="big"))
            client_socket.send(public_bytes)
            print("📤 Sent our public key to Ruby peer")
            
        except Exception as e:
            print(f"❌ Error during key exchange: {e}")
    
    def handle_file_list_request(self, client_socket):
        try:
            # Get list of files
            files = []
            for filename in os.listdir("Files"):
                # Create file info with hash
                file_path = os.path.join("Files", filename)
                if os.path.isfile(file_path):
                    file_hash = "dummy_hash_" + os.urandom(4).hex()  # Simplified
                    files.append({"name": filename, "hash": file_hash})
            
            # Send response
            client_socket.send(b"L")
            response = json.dumps(files).encode()
            client_socket.send(len(response).to_bytes(4, byteorder="big"))
            client_socket.send(response)
            print("📤 Sent file list to Ruby peer")
            
        except Exception as e:
            print(f"❌ Error sending file list: {e}")
    
    def handle_file_request(self, client_socket, client_address):
        global session_key, auto_accept_requests
        
        try:
            # Read request
            length = int.from_bytes(client_socket.recv(4), byteorder="big")
            payload = client_socket.recv(length)
            request = json.loads(payload.decode())
            
            filename = request.get("file_name")
            print(f"📥 File request from {client_address[0]} for '{filename}'")
            
            filepath = os.path.join("Files", filename)
            
            # Check if file exists
            if not os.path.exists(filepath):
                response = {"status": "rejected", "message": "File not found"}
                client_socket.send(b"F")
                client_socket.send(len(json.dumps(response).encode()).to_bytes(4, byteorder="big"))
                client_socket.send(json.dumps(response).encode())
                print(f"❌ File '{filename}' not found")
                return
            
            # Ask for confirmation (or auto-accept)
            if not auto_accept_requests:
                answer = input(f"Allow sending '{filename}' to {client_address[0]}? (y/n): ").strip().lower()
                if answer != 'y':
                    response = {"status": "rejected", "message": "Request denied by user"}
                    client_socket.send(b"F")
                    client_socket.send(len(json.dumps(response).encode()).to_bytes(4, byteorder="big"))
                    client_socket.send(json.dumps(response).encode())
                    print("❌ File transfer denied by user")
                    return
            else:
                print(f"🤖 Auto-accepting file request for '{filename}'")
            
            # Load file content
            with open(filepath, 'rb') as f:
                file_content = f.read()
            
            # Send acceptance
            response = {"status": "accepted"}
            client_socket.send(b"F")
            client_socket.send(len(json.dumps(response).encode()).to_bytes(4, byteorder="big"))
            client_socket.send(json.dumps(response).encode())
            
            # Encrypt file if we have a session key
            if session_key:
                encrypted = encrypt_file(file_content, session_key)
                
                # Send encrypted data
                client_socket.send(b"D")
                client_socket.send(len(encrypted["iv"]).to_bytes(4, byteorder="big"))
                client_socket.send(encrypted["iv"])
                client_socket.send(len(encrypted["tag"]).to_bytes(4, byteorder="big"))
                client_socket.send(encrypted["tag"])
                client_socket.send(len(encrypted["ciphertext"]).to_bytes(4, byteorder="big"))
                client_socket.send(encrypted["ciphertext"])
                
                print(f"✅ Encrypted and sent file '{filename}'")
            else:
                print("❌ No session key available, cannot encrypt file")
                # Send error response
                client_socket.send(b"E")
                error = {"error": "No session key available"}
                client_socket.send(len(json.dumps(error).encode()).to_bytes(4, byteorder="big"))
                client_socket.send(json.dumps(error).encode())
            
        except Exception as e:
            print(f"❌ Error handling file request: {e}")
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Python Test Peer for Ruby-Python interoperability testing")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=5003, help="Port to listen on")
    parser.add_argument("--auto", action="store_true", help="Auto-accept file transfer requests")
    
    args = parser.parse_args()
    
    # Set auto-accept flag
    auto_accept_requests = args.auto
    
    # Start test peer
    test_peer = TestPeer(args.host, args.port)
    try:
        test_peer.start()
    except KeyboardInterrupt:
        print("\nExiting...") 