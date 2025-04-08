import asyncio
import os
import sys
import subprocess
import socket
import json
import hashlib
from getpass import getpass

from advertise import advertise_service, stop_advertisement
from discover import discover_peers
from client import (
    request_file, 
    perform_key_exchange_with_ruby, 
    request_file_list,
    save_peer_file_list,
    verify_file_hash
)
from identity import sign_session_key, create_identity, send_identity_to_ruby, rotate_public_key, notify_peers_of_rotation, ensure_identity_exists
from file_server import FileServer
from storage import SecureStorage

def is_port_in_use(port, host='0.0.0.0'):
    """Check if the specified port is already in use"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return False
        except OSError:
            return True

def manage_files():
    """Manage files - encrypt or decrypt files"""
    storage = SecureStorage()
    
    # List all files with their encryption status
    all_files = storage.list_all_files()
    
    if not all_files:
        print("❌ No files found in the Received directory.")
        return
    
    # Separate files into encrypted and non-encrypted
    encrypted_files = [f for f in all_files if f['encrypted']]
    non_encrypted_files = [f for f in all_files if not f['encrypted']]
    
    print("\n📁 Files available:")
    print("🔐 Encrypted files:")
    for i, file_info in enumerate(encrypted_files, 1):
        print(f"{i}. {file_info['filename']}")
    
    print("\n📄 Non-encrypted files:")
    for i, file_info in enumerate(non_encrypted_files, 1):
        print(f"{i}. {file_info['filename']}")
    
    action = input("\nSelect action (1=decrypt, 2=encrypt): ").strip()
    
    if action == "1" and encrypted_files:
        # Decrypt an encrypted file
        try:
            idx = int(input("Select encrypted file to decrypt (number): ")) - 1
            if idx < 0 or idx >= len(encrypted_files):
                print("❌ Invalid selection.")
                return
                
            filename = encrypted_files[idx]['filename']
            
            # Ask for password
            password = getpass("Enter decryption password: ")
            if not password:
                print("❌ Password cannot be empty.")
                return
            
            # Get output path
            output_filename = filename.rsplit('.enc', 1)[0]
            custom_path = input(f"Enter output path (default: Received/{output_filename}): ").strip()
            
            if not custom_path:
                output_path = os.path.join("Received", output_filename)
            else:
                output_path = custom_path
            
            # Decrypt the file
            decrypted_path = storage.get_decrypted_file(filename, password, output_path)
            
            if decrypted_path:
                print(f"✅ File successfully decrypted to: {decrypted_path}")
            else:
                print("❌ Decryption failed. Incorrect password or corrupted file.")
                
        except (ValueError, IndexError) as e:
            print(f"❌ Error: {e}")
    
    elif action == "2" and non_encrypted_files:
        # Encrypt a non-encrypted file
        try:
            idx = int(input("Select non-encrypted file to encrypt (number): ")) - 1
            if idx < 0 or idx >= len(non_encrypted_files):
                print("❌ Invalid selection.")
                return
                
            filename = non_encrypted_files[idx]['filename']
            filepath = os.path.join("Received", filename)
            
            # Ask for password
            password = getpass("Enter encryption password: ")
            if not password:
                print("❌ Password cannot be empty.")
                return
                
            # Read file content
            with open(filepath, 'rb') as f:
                file_content = f.read()
                
            # Encrypt the file
            encrypted_path = storage.store_encrypted_file(file_content, filename, password)
            
            # Ask if user wants to keep the original file
            keep_original = input("Keep original non-encrypted file? (y/n): ").strip().lower()
            if keep_original != 'y':
                try:
                    os.remove(filepath)
                    print(f"✅ Removed original file: {filepath}")
                except Exception as e:
                    print(f"❌ Failed to remove original file: {e}")
            
            print(f"✅ File successfully encrypted to: {encrypted_path}")
                
        except (ValueError, IndexError, Exception) as e:
            print(f"❌ Error: {e}")
    
    else:
        print("❌ Invalid selection or no files of the selected type.")

def ensure_known_peers_file_exists():
    """Make sure the known_peers.json file exists, create it if it doesn't"""
    try:
        current_dir = os.getcwd()
        file_path = os.path.join(current_dir, 'known_peers.json')
        
        if not os.path.exists(file_path):
            print(f"Creating known_peers.json file at {file_path}")
            with open(file_path, 'w') as f:
                json.dump({}, f)
            print("✅ known_peers.json initialized successfully")
        return True
    except Exception as e:
        print(f"❌ Error initializing known_peers.json: {e}")
        import traceback
        traceback.print_exc()
        return False

def main(start_server=True):
    print("🔁 Starting P2P Python Client")
    service_name = advertise_service()
    
    # Initialize known_peers.json file
    ensure_known_peers_file_exists()
    
    # Only start the file server if it's not already running
    if start_server and not is_port_in_use(5003):
        print("Starting file server...")
        subprocess.Popen([sys.executable, "file_server.py"])
    elif start_server:
        print("File server already running. Continuing with client mode only.")

    while True:
        print("\nMenu:")
        print("1. Find peers")
        print("2. Request File")
        print("3. 🔐 Create Identity")
        print("4. Request File List")
        print("5. 📁 Manage Received Files")
        print("6. Rotate Identity Key")
        print("7. 🌐 Find File from Alternative Source")
        print("0. Exit")

        choice = input("Enter choice: ")

        if choice == "1":
            peers = discover_peers()
            if not peers:
                print("❌ No peers found.")
            else:
                print("\n✅ Discovered Peers:")
                for i, peer in enumerate(peers, 1):
                    print(f"{i}. {peer['name']} @ {peer['ip']}:{peer['port']}")

        elif choice == "2":
            # Check if identity exists first
            if not ensure_identity_exists():
                continue
                
            peers = discover_peers()
            if not peers:
                print("No peers found.")
                continue

            print("\nChoose a peer to request from:")
            for i, peer in enumerate(peers):
                print(f"{i+1}. {peer['name']} @ {peer['ip']}:{peer['port']}")
            try:
                idx = int(input("Peer number: ")) - 1
                peer = peers[idx]
                filename = input("Enter filename to request: ").strip()

                # Perform ECDH key exchange
                session_key = perform_key_exchange_with_ruby(peer["ip"], peer["port"])
                if not session_key:
                    print("❌ Key exchange failed.")
                    continue
                
                identity_payload = sign_session_key(session_key)
                response = send_identity_to_ruby(peer["ip"], peer["port"], identity_payload)
                if response:
                    # Request the file list first to store hashes for this peer
                    request_file_list(peer["ip"], peer["port"], peer["name"])
                    # Then request the file
                    request_file(peer["ip"], peer["port"], filename, session_key, peer["name"])
                else:
                    print("error with identitfication")

            except (ValueError, IndexError):
                print("Invalid selection.")

        elif choice == "3":
            create_identity()
        elif choice == "4":
            peers = discover_peers()
            if not peers:
                print("❌ No peers found.")
                continue

            print("\nChoose a peer to get file list from:")
            for i, peer in enumerate(peers):
                print(f"{i+1}. {peer['name']} @ {peer['ip']}:{peer['port']}")
            try:
                idx = int(input("Peer number: ")) - 1
                peer = peers[idx]
                request_file_list(peer["ip"], peer["port"], peer["name"])
            except (ValueError, IndexError):
                print("❌ Invalid selection.")
        elif choice == "5":
            manage_files()
        elif choice =="6":
            migrate_msg = rotate_public_key()
            if migrate_msg:
                notify_peers_of_rotation(migrate_msg)
        elif choice == "7":
            # Finding files from alternative sources with hash verification
            if not os.path.exists("known_peers.json"):
                print("❌ No known peers data. Please use option 4 to fetch file lists first.")
                continue
                
            try:
                # Load known peers to find files
                with open("known_peers.json", "r") as f:
                    peers_data = json.load(f)
                
                # Create a mapping of peers having each file
                available_files = {}
                for peer_name, peer_info in peers_data.items():
                    if isinstance(peer_info, dict) and "files" in peer_info:
                        for file_info in peer_info["files"]:
                            if isinstance(file_info, dict):
                                filename = file_info["name"]
                                if filename not in available_files:
                                    available_files[filename] = []
                                available_files[filename].append({
                                    "peer": peer_name,
                                    "hash": file_info["hash"]
                                })
                
                if not available_files:
                    print("❌ No files found in known peers.")
                    continue
                
                # Show available files
                print("\n📃 Files available from all known peers:")
                file_list = list(available_files.keys())
                for i, filename in enumerate(file_list):
                    peers_with_file = [info["peer"] for info in available_files[filename]]
                    print(f"{i+1}. {filename} (Available from: {', '.join(peers_with_file)})")
                
                # Ask which file to download
                file_idx = int(input("\nWhich file do you want to download? (number): ")) - 1
                if file_idx < 0 or file_idx >= len(file_list):
                    print("❌ Invalid selection.")
                    continue
                
                filename = file_list[file_idx]
                
                # Show available sources for this file
                print(f"\n🌐 Available sources for '{filename}':")
                sources = available_files[filename]
                for i, source in enumerate(sources):
                    print(f"{i+1}. {source['peer']} (Hash: {source['hash']})")
                
                # Ask which source to use
                source_idx = int(input("\nWhich source do you want to use? (number): ")) - 1
                if source_idx < 0 or source_idx >= len(sources):
                    print("❌ Invalid selection.")
                    continue
                
                selected_source = sources[source_idx]
                original_peer = selected_source["peer"]
                
                # Now find an active peer to download from
                active_peers = discover_peers()
                active_peer_names = [p["name"] for p in active_peers]
                
                if original_peer in active_peer_names:
                    # Original peer is online, download directly
                    print(f"✅ Original peer '{original_peer}' is online. Downloading directly.")
                    peer = next(p for p in active_peers if p["name"] == original_peer)
                    
                    # Perform key exchange with the peer
                    session_key = perform_key_exchange_with_ruby(peer["ip"], peer["port"])
                    if not session_key:
                        print("❌ Key exchange failed.")
                        continue
                    
                    identity_payload = sign_session_key(session_key)
                    response = send_identity_to_ruby(peer["ip"], peer["port"], identity_payload)
                    if response:
                        request_file(peer["ip"], peer["port"], filename, session_key, original_peer)
                    else:
                        print("❌ Error with identification")
                else:
                    # Original peer is offline, try to find alternative source
                    print(f"⚠️ Original peer '{original_peer}' is offline. Looking for alternative sources...")
                    
                    # Ask which active peer to try
                    print("\n🔍 Active peers that might have the file:")
                    for i, peer in enumerate(active_peers):
                        print(f"{i+1}. {peer['name']} @ {peer['ip']}:{peer['port']}")
                    
                    peer_idx = int(input("\nWhich peer to try? (number): ")) - 1
                    if peer_idx < 0 or peer_idx >= len(active_peers):
                        print("❌ Invalid selection.")
                        continue
                    
                    alternative_peer = active_peers[peer_idx]
                    
                    # Perform key exchange with the alternative peer
                    session_key = perform_key_exchange_with_ruby(alternative_peer["ip"], alternative_peer["port"])
                    if not session_key:
                        print("❌ Key exchange failed.")
                        continue
                    
                    identity_payload = sign_session_key(session_key)
                    response = send_identity_to_ruby(alternative_peer["ip"], alternative_peer["port"], identity_payload)
                    if response:
                        print(f"⚠️ Downloading from alternative peer '{alternative_peer['name']}' with verification against original peer '{original_peer}'")
                        request_file(alternative_peer["ip"], alternative_peer["port"], filename, session_key, original_peer)
                    else:
                        print("❌ Error with identification")
                
            except Exception as e:
                print(f"❌ Error: {e}")
                import traceback
                traceback.print_exc()
        elif choice == "0":
            stop_advertisement()
            break

        else:
            print("Invalid choice.")

def start():
    print("Welcome to P2P File Share")
    print("1. Receive a file")
    print("2. Send a file (standby to recieve file request)")
    choice = input("Select your role (1 or 2): ").strip()

    if choice == "1":
        print("📤 Starting in reciever mode...")
        main(start_server=True)
        
    elif choice == "2":
        print("📥 Starting in send mode...")
        service_name = advertise_service()
        server = FileServer()
        print("👋 Press Ctrl+C to stop the server at any time.")

        try:
            server.start()  # runs in the foreground so input() works
        except KeyboardInterrupt:
            print("\n🛑 Shutting down...")
            stop_advertisement()
            sys.exit(0)
    else:
        print("❌ Invalid selection.")
        sys.exit(1)

if __name__ == "__main__":
    start()
