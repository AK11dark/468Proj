import asyncio
import os
import sys
import subprocess
import socket
import json
import hashlib
from getpass import getpass

from advertise import advertise_service, stop_advertisement
from discover import discover_peers, set_own_service_name
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

def handle_find_peers():
    peers = discover_peers()
    if not peers:
        print("❌ No peers found.")
    else:
        print("\n✅ Discovered Peers:")
        for i, peer in enumerate(peers, 1):
            print(f"{i}. {peer['name']} @ {peer['ip']}:{peer['port']}")

def handle_request_file():
    # Check if identity exists first
    if not ensure_identity_exists():
        return
        
    peers = discover_peers()
    if not peers:
        print("No peers found.")
        return

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
            return
        
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

def handle_request_file_list():
    peers = discover_peers()
    if not peers:
        print("❌ No peers found.")
        return

    print("\nChoose a peer to get file list from:")
    for i, peer in enumerate(peers):
        print(f"{i+1}. {peer['name']} @ {peer['ip']}:{peer['port']}")
    try:
        idx = int(input("Peer number: ")) - 1
        peer = peers[idx]
        request_file_list(peer["ip"], peer["port"], peer["name"])
    except (ValueError, IndexError):
        print("❌ Invalid selection.")

def handle_rotate_key():
    migrate_msg = rotate_public_key()
    if migrate_msg:
        notify_peers_of_rotation(migrate_msg)

def handle_find_alternative_source():
    # Finding files from alternative sources with hash verification
    if not os.path.exists("known_peers.json"):
        print("❌ No known peers data. Please use option 4 to fetch file lists first.")
        return
        
    try:
        # First discover active peers
        active_peers = discover_peers()
        if not active_peers:
            print("❌ No active peers found.")
            return
            
        active_peer_names = [p["name"] for p in active_peers]
        print(f"✅ Found {len(active_peers)} active peers: {', '.join(active_peer_names)}")
        
        # Check for new peers and request their file lists first
        with open("known_peers.json", "r") as f:
            peers_data = json.load(f)
        
        new_peers = [p for p in active_peers if p["name"] not in peers_data]
        if new_peers:
            print("\n🔄 Requesting file lists from newly discovered peers...")
            for peer in new_peers:
                print(f"Requesting file list from {peer['name']}...")
                request_file_list(peer["ip"], peer["port"], peer["name"])
            
            # Reload the peers data after getting new file lists
            with open("known_peers.json", "r") as f:
                peers_data = json.load(f)
        
        # Create a mapping of all known files regardless of peer status
        all_known_files = {}
        for peer_name, peer_info in peers_data.items():
            if isinstance(peer_info, dict) and "files" in peer_info:
                for file_info in peer_info["files"]:
                    if isinstance(file_info, dict):
                        filename = file_info["name"]
                        if filename not in all_known_files:
                            all_known_files[filename] = []
                        all_known_files[filename].append({
                            "peer": peer_name,
                            "hash": file_info["hash"],
                            "active": peer_name in active_peer_names
                        })
        
        if not all_known_files:
            print("❌ No files found in known peers.")
            return
        
        # Show all available files and indicate which are from active peers
        print("\n📃 All files known in the network:")
        file_list = list(all_known_files.keys())
        for i, filename in enumerate(file_list):
            # Separate active and inactive peers
            active_peers_with_file = [info["peer"] for info in all_known_files[filename] if info["active"]]
            inactive_peers_with_file = [info["peer"] for info in all_known_files[filename] if not info["active"]]
            
            active_status = f"✅ Available from: {', '.join(active_peers_with_file)}" if active_peers_with_file else "❌ No active peers have this file"
            inactive_status = f" (Also known by inactive peers: {', '.join(inactive_peers_with_file)})" if inactive_peers_with_file else ""
            
            print(f"{i+1}. {filename} - {active_status}{inactive_status}")
        
        # Ask which file to download
        file_idx = int(input("\nWhich file do you want to download? (number): ")) - 1
        if file_idx < 0 or file_idx >= len(file_list):
            print("❌ Invalid selection.")
            return
        
        filename = file_list[file_idx]
        
        # Check if any active peers have this file
        active_sources = [s for s in all_known_files[filename] if s["active"]]
        
        if not active_sources:
            print(f"❌ No active peers have the file '{filename}'. Try again when peers are online.")
            return
        
        # Show available active sources for this file
        print(f"\n🌐 Active sources for '{filename}':")
        for i, source in enumerate(active_sources):
            print(f"{i+1}. {source['peer']} (Hash: {source['hash']})")
        
        # Ask which source to use
        source_idx = int(input("\nWhich source do you want to use? (number): ")) - 1
        if source_idx < 0 or source_idx >= len(active_sources):
            print("❌ Invalid selection.")
            return
        
        selected_source = active_sources[source_idx]
        selected_peer_name = selected_source["peer"]
        selected_peer = next(p for p in active_peers if p["name"] == selected_peer_name)
        
        # Perform key exchange with the peer
        session_key = perform_key_exchange_with_ruby(selected_peer["ip"], selected_peer["port"])
        if not session_key:
            print("❌ Key exchange failed.")
            return
        
        identity_payload = sign_session_key(session_key)
        response = send_identity_to_ruby(selected_peer["ip"], selected_peer["port"], identity_payload)
        if response:
            # Check if we should verify against another peer's hash
            all_sources = all_known_files[filename]
            other_sources = [s for s in all_sources if s["peer"] != selected_peer_name]
            
            if other_sources:
                print("\nWould you like to verify against another peer's hash?")
                verify = input("Verify against another source? (y/n): ").lower().strip() == 'y'
                
                if verify:
                    # Show other sources for verification (including inactive for hash checking)
                    print("\nChoose a source to verify against (active or inactive):")
                    for i, source in enumerate(other_sources):
                        status = "✅ Active" if source["active"] else "❌ Inactive"
                        print(f"{i+1}. {source['peer']} ({status}) - Hash: {source['hash']}")
                    
                    try:
                        verify_idx = int(input("Verification source (number): ")) - 1
                        if 0 <= verify_idx < len(other_sources):
                            verification_peer = other_sources[verify_idx]["peer"]
                            print(f"✅ Downloading from '{selected_peer_name}' with verification against '{verification_peer}'")
                            request_file(selected_peer["ip"], selected_peer["port"], filename, session_key, verification_peer)
                        else:
                            print("❌ Invalid selection, downloading without verification.")
                            request_file(selected_peer["ip"], selected_peer["port"], filename, session_key, selected_peer_name)
                    except ValueError:
                        print("❌ Invalid input, downloading without verification.")
                        request_file(selected_peer["ip"], selected_peer["port"], filename, session_key, selected_peer_name)
                else:
                    request_file(selected_peer["ip"], selected_peer["port"], filename, session_key, selected_peer_name)
            else:
                request_file(selected_peer["ip"], selected_peer["port"], filename, session_key, selected_peer_name)
        else:
            print("❌ Error with identification")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

def main():
    print("🔁 Starting P2P Python Client")
    service_name = advertise_service()
    
    # Store our own service name to prevent self-discovery
    set_own_service_name(service_name)
    
    # Initialize known_peers.json file
    ensure_known_peers_file_exists()
    
    # Start the file server if it's not already running
    if not is_port_in_use(5003):
        print("Starting file server...")
        subprocess.Popen([sys.executable, "file_server.py"])
    else:
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
            handle_find_peers()
        elif choice == "2":
            handle_request_file()
        elif choice == "3":
            create_identity()
        elif choice == "4":
            handle_request_file_list()
        elif choice == "5":
            manage_files()
        elif choice == "6":
            handle_rotate_key()
        elif choice == "7":
            handle_find_alternative_source()
        elif choice == "0":
            stop_advertisement()
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()
