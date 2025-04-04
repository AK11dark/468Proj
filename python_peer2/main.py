from advertise import advertise_service, stop_advertisement
from discover import discover_peers
from client import request_file
from client import test_ping

def main():
    print("🔁 Starting P2P Python Client")
    service_name = advertise_service()

    while True:
        print("\nMenu:")
        print("1. Find peers")
        print("2. Request File")
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
                #request_file(peer["ip"], peer["port"], filename)
                print(peer["ip"], peer["port"])
                test_ping(peer["ip"], peer["port"])

            except (ValueError, IndexError):
                print("Invalid selection.")

        elif choice == "0":
            stop_advertisement()
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
