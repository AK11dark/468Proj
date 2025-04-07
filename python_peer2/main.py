from advertise import advertise_service, stop_advertisement
from discover import discover_peers
from client import request_file, test_ping, perform_key_exchange_with_ruby
from identity import create_identity, sign_session_key, send_identity_to_ruby  # ✅ This is your identity setup
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import subprocess

def main():
    print("🔁 Starting P2P Python Client")
    service_name = advertise_service()
    subprocess.Popen(["python3", "file_server.py"])

    while True:
        print("\nMenu:")
        print("1. Find peers")
        print("2. Request File")
        print("3. 🔐 Create Identity")
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

        elif choice == "0":
            stop_advertisement()
            break

        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
