import asyncio
from discovery_service import DiscoveryService
import sys

async def handle_user_input(service):
    """Handle user input while the service is running"""
    while True:
        print("\nCommands:")
        print("1. List all peers")
        print("2. Update shared files")
        print("3. Exit")
        try:
            command = await asyncio.get_event_loop().run_in_executor(None, input, "\nEnter command (1-3): ")
            
            if command == "1":
                peers = service.discovery.get_peers()
                if not peers:
                    print("\nNo peers found yet.")
                else:
                    print("\nCurrent Peers:")
                    for name, data in peers.items():
                        print(f"\nPeer: {name}")
                        print(f"  Address: {data['address']}:{data['port']}")
                        print(f"  Shared files: {data['files']}")
                        
            elif command == "2":
                files = await asyncio.get_event_loop().run_in_executor(
                    None, input, "\nEnter comma-separated list of files to share: "
                )
                file_list = [f.strip() for f in files.split(",")]
                service.update_files(file_list)
                print(f"\nUpdated shared files: {file_list}")
                
            elif command == "3":
                print("\nShutting down...")
                await service.stop()
                sys.exit(0)
                
        except Exception as e:
            print(f"\nError: {e}")

async def main():
    # Create the discovery service
    service = DiscoveryService(port=5000)
    
    # Initial files to share
    service.update_files(["file1.txt", "file2.txt"])
    
    try:
        asyncio.create_task(handle_user_input(service))
        await service.run()
    finally:
        await service.stop()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nProgram terminated by user")