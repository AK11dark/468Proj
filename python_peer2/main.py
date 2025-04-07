from advertise import advertise_service, stop_advertisement
from discover import discover_peers
from client import request_file, perform_key_exchange_with_ruby, request_file_list
from identity import create_identity, sign_session_key, send_identity_to_ruby  # ✅ This is your identity setup
from storage import SecureStorage
import os
from getpass import getpass
from identity import rotate_public_key, notify_peers_of_rotation
import subprocess
import socket
import sys

def is_port_in_use(port, host='0.0.0.0'):
    """Check if the specified port is already in use"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return False
        except OSError:
            return True

def decrypt_stored_file():
    """Decrypt a previously encrypted file using the provided password"""
    storage = SecureStorage()
    
    # List encrypted files
    encrypted_files = storage.list_encrypted_files()
    
    if not encrypted_files:
        print("❌ No encrypted files found in the Received directory.")
        return
    
    print("\n🔐 Encrypted files available:")
    for i, filename in enumerate(encrypted_files, 1):
        print(f"{i}. {filename}")
    
    try:
        idx = int(input("Select file to decrypt (number): ")) - 1
        if idx < 0 or idx >= len(encrypted_files):
            print("❌ Invalid selection.")
            return
            
        filename = encrypted_files[idx]
        
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

def main(start_server=True):
    print("🔁 Starting P2P Python Client")
    service_name = advertise_service()
    
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
        print("5. 🔓 Decrypt Stored File")
        print("6. Rotate Identity Key")
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
                    request_file(peer["ip"], peer["port"], filename, session_key)
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
                request_file_list(peer["ip"], peer["port"])
            except (ValueError, IndexError):
                print("❌ Invalid selection.")
        elif choice == "5":
            decrypt_stored_file()
        elif choice =="6":
            migrate_msg = rotate_public_key()
            if migrate_msg:
                notify_peers_of_rotation(migrate_msg)
        elif choice == "0":
            stop_advertisement()
            break

        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
