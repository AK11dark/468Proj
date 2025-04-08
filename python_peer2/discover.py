import socket
import time
from zeroconf import Zeroconf, ServiceBrowser, ServiceListener

# Store our own service name globally
OWN_SERVICE_NAME = None

def set_own_service_name(service_name):
    """Set the service name of this client to filter out self-discovery"""
    global OWN_SERVICE_NAME
    OWN_SERVICE_NAME = service_name
    print(f"Setting own service name: {OWN_SERVICE_NAME}")

class PeerListener(ServiceListener):
    def __init__(self):
        self.peers = []

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

    def remove_service(self, zeroconf, service_type, name):
        # Optional: You can print or update a list
        pass

    def update_service(self, zeroconf, service_type, name):
        # Optional: You can re-fetch info here
        pass

def discover_peers(timeout=10):
    zeroconf = Zeroconf()
    listener = PeerListener()
    browser = ServiceBrowser(zeroconf, "_peer._tcp.local.", listener)

    print("🔍 Browsing for _peer._tcp.local services...")
    time.sleep(timeout)
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

