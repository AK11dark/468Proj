import socket
import time
from zeroconf import Zeroconf, ServiceBrowser, ServiceListener

# Store our own service name globally
OWN_SERVICE_NAME = None

def set_own_service_name(service_name):
    """Set the service name of this client to filter out self-discovery"""
    global OWN_SERVICE_NAME
    OWN_SERVICE_NAME = service_name
    # Only print this in debug mode or when running discover.py directly

class PeerListener(ServiceListener):
    def __init__(self):
        self.peers = []
        self.last_discovery = 0

    def add_service(self, zeroconf, service_type, name):
        # Skip if this is our own service
        global OWN_SERVICE_NAME
        if OWN_SERVICE_NAME and name == OWN_SERVICE_NAME:
            print(f"Skipping own service: {name}")
            return
            
        info = zeroconf.get_service_info(service_type, name)
        if info and info.addresses:
            ip = socket.inet_ntoa(info.addresses[0])
            props = {k.decode(): v.decode() for k, v in info.properties.items()}
            network_port = int(props.get("network_port", info.port))

            self.peers.append({
                "name": name,
                "ip": ip,
                "port": network_port
            })
            print(f"Discovered peer: {name} @ {ip}:{network_port}")
            # Update last discovery time
            self.last_discovery = time.time()

    def remove_service(self, zeroconf, service_type, name):
        # Optional: You can print or update a list
        pass

    def update_service(self, zeroconf, service_type, name):
        # Optional: You can re-fetch info here
        pass

def discover_peers(timeout=5):  # Reduced default timeout
    zeroconf = Zeroconf()
    listener = PeerListener()
    browser = ServiceBrowser(zeroconf, "_peer._tcp.local.", listener)

    print("🔍 Browsing for _peer._tcp.local services...")
    
    # Use a more responsive approach to wait for responses
    start_time = time.time()
    found_peers = False
    min_wait = 1.0  # Minimum time to wait even if peers are found
    
    while time.time() - start_time < timeout:
        # Check if we've found any peers
        if listener.peers:
            found_peers = True
            # If we've already waited min_wait seconds since the last discovery, we can exit early
            if time.time() - listener.last_discovery > min_wait:
                break
                
        # Short sleep to avoid busy waiting
        time.sleep(0.2)
    
    zeroconf.close()

    return listener.peers

if __name__ == "__main__":
    peers = discover_peers()
    if peers:
        print("\n✅ Final list of peers:")
        for i, peer in enumerate(peers, 1):
            print(f"{i}. {peer['name']} @ {peer['ip']}:{peer['port']}")
    else:
        print("❌ No peers found.")

