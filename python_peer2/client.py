# file_request.py
import socket
import json
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from storage import SecureStorage
from getpass import getpass
import hashlib
import time


def request_file(ip, port, filename, session_key, original_peer_name=None):
    # Check if already authenticated with this peer
    authenticated = False
    
    if original_peer_name and os.path.exists("authenticated_peers.json"):
        try:
            with open("authenticated_peers.json", "r") as f:
                auth_data = json.load(f)
                
                # Handle various possible peer name formats
                peer_keys = [original_peer_name]
                
                # Add variations of the name for matching
                if '_peer._tcp.local' in original_peer_name:
                    base_name = original_peer_name.split('._peer._tcp.local')[0]
                    peer_keys.append(base_name)
                    peer_keys.append(f"{base_name}._peer._tcp.local")
                
                # Try each variation to find a match
                matched_key = None
                for key in peer_keys:
                    if key in auth_data:
                        matched_key = key
                        break
                        
                if matched_key:
                    peer_data = auth_data[matched_key]
                    auth_time = time.strftime('%Y-%m-%d %H:%M:%S', 
                                             time.localtime(peer_data["last_auth"]))
                    print(f"🔑 Previously authenticated with {original_peer_name} at {auth_time}")
                    authenticated = True
                    
        except (json.JSONDecodeError, FileNotFoundError) as e:
            print(f"⚠️ Error reading authentication data: {e}")
    
    if not authenticated:
        print("⚠️ Not yet authenticated with this peer.")
        print("ℹ️ Consider using option 8 from the main menu to authenticate first.")
    
    os.makedirs("Received", exist_ok=True)

    with socket.create_connection((ip, port)) as sock:
        # Send file request
        request = { "file_name": filename }
        request_bytes = json.dumps(request).encode("utf-8")
        sock.send(b"F")
        sock.send(len(request_bytes).to_bytes(4, 'big'))
        sock.send(request_bytes)
        print(f"📤 Sent request for file '{filename}' to {ip}:{port}")

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
            
        # Verify file hash if original_peer_name is provided
        if original_peer_name:
            hash_verified = verify_file_hash(filename, plaintext, original_peer_name)
            if not hash_verified:
                print("⚠️ WARNING: File hash verification failed. The file may have been tampered with.")
                save_anyway = input("Do you still want to save this file? (y/n): ").strip().lower()
                if save_anyway != 'y':
                    print("❌ File download canceled.")
                    return
                print("⚠️ Proceeding with unverified file...")
            else:
                print("✅ File hash verified successfully.")

        # Ask if the user wants to encrypt the file
        storage = SecureStorage()
        encrypt_choice = input("\n🔒 Do you want to encrypt the file locally? (y/n): ").strip().lower()
        
        if encrypt_choice == 'y':
            # Ask user for a password to encrypt the file locally
            password = getpass("Enter password for local encryption: ")
            if not password:
                print("❌ Password cannot be empty, saving without encryption")
                save_path = storage.store_file(plaintext, filename)
                print(f"✅ File '{filename}' saved without encryption to {save_path}")
            else:
                # Use SecureStorage to store the file with encryption
                encrypted_path = storage.store_encrypted_file(plaintext, filename, password)
                print(f"✅ File '{filename}' encrypted with password and saved to {encrypted_path}")
                print("To decrypt this file later, use the same password.")
        else:
            # Save without encryption
            save_path = storage.store_file(plaintext, filename)
            print(f"✅ File '{filename}' saved without encryption to {save_path}")
            
        return plaintext  # Return the file content for further processing if needed

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

def save_peer_file_list(peer_name, file_list, silent=False):
    """Save a peer's file list with hashes to known_peers.json"""
    try:
        # File path for known_peers.json
        current_dir = os.getcwd()
        file_path = os.path.join(current_dir, 'known_peers.json')
        
        # Load existing known_peers.json
        peers_data = {}
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r') as f:
                    peers_data = json.load(f)
            except json.JSONDecodeError:
                if not silent:
                    print(f"⚠️ Error parsing existing known_peers.json, will create new file")
        
        # Add or update file_list for this peer
        if peer_name not in peers_data:
            peers_data[peer_name] = {}
        
        # Keep the public key if it exists
        if isinstance(peers_data[peer_name], str):
            public_key = peers_data[peer_name]
            peers_data[peer_name] = {
                "public_key": public_key,
                "files": file_list
            }
        else:
            # If it's already a dictionary, just update the files
            peers_data[peer_name]["files"] = file_list
        
        # Save updated data
        try:
            with open(file_path, 'w') as f:
                json.dump(peers_data, f, indent=2)
            if not silent:
                print(f"💾 Saved file list for peer '{peer_name}'")
            return True
        except PermissionError:
            if not silent:
                print(f"❌ Permission denied when saving peer file list")
            return False
        except IOError as e:
            if not silent:
                print(f"❌ Error saving peer file list: {e}")
            return False
            
    except Exception as e:
        if not silent:
            print(f"❌ Error saving peer file list: {e}")
        return False

def request_file_list(ip, port, peer_name=None):
    try:
        with socket.create_connection((ip, port), timeout=5) as sock:
            sock.send(b"L")  # Request file list

            resp_type = sock.recv(1)
            if resp_type != b"L":
                print("❌ Unexpected response type:", resp_type)
                return

            length = int.from_bytes(sock.recv(4), 'big')
            data = sock.recv(length).decode()
            file_list = json.loads(data)

            print("\n📃 Files available on peer:")
            for i, file_info in enumerate(file_list, 1):
                if isinstance(file_info, dict):
                    print(f"{i}. {file_info['name']} (Hash: {file_info['hash']})")
                else:
                    # Handle legacy format without hashes
                    print(f"{i}. {file_info}")
            
            # If peer_name is provided, store the file list with hashes in known_peers.json
            if peer_name:
                save_peer_file_list(peer_name, file_list)
            
            return file_list

    except Exception as e:
        print("❌ Failed to get file list:", e)
        return None

def verify_file_hash(filename, file_content, peer_name):
    """Verify that a file's hash matches what was advertised by the original peer"""
    try:
        # Get absolute path to known_peers.json
        current_dir = os.getcwd()
        file_path = os.path.join(current_dir, 'known_peers.json')
        
        # Load known_peers.json
        if not os.path.exists(file_path):
            print(f"❌ known_peers.json does not exist at {file_path}")
            return False
            
        with open(file_path, 'r') as f:
            peers_data = json.load(f)
            
        # Check if peer exists and has file list
        if peer_name not in peers_data or not isinstance(peers_data[peer_name], dict) or "files" not in peers_data[peer_name]:
            print(f"❌ No file list found for peer '{peer_name}'")
            return False
            
        # Calculate the hash of the received file
        sha256 = hashlib.sha256()
        sha256.update(file_content)
        calculated_hash = sha256.hexdigest()
        
        # Check against stored hash
        for file_info in peers_data[peer_name]["files"]:
            if isinstance(file_info, dict) and file_info["name"] == filename:
                expected_hash = file_info["hash"]
                if calculated_hash == expected_hash:
                    print(f"✅ File hash verified for '{filename}'")
                    return True
                else:
                    print(f"❌ File hash mismatch for '{filename}'")
                    print(f"Expected: {expected_hash}")
                    print(f"Received: {calculated_hash}")
                    return False
                    
        print(f"❌ File '{filename}' not found in peer's file list")
        return False
        
    except Exception as e:
        print(f"❌ Error verifying file hash: {e}")
        import traceback
        traceback.print_exc()
        return False
