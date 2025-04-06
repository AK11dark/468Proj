from file_server import FileServer
from main import main  #menu based client
from advertise import advertise_service, stop_advertisement
import sys

def start():
    print("Welcome to P2P File Share")
    print("1. Receive a file")
    print("2. Send a file (standby to recieve file request)")
    choice = input("Select your role (1 or 2): ").strip()

    if choice == "1":
        print("📤 Starting in reciever mode...")
        main()
        
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
