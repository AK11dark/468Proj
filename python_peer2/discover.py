import socket
import time
from zeroconf import Zeroconf, ServiceBrowser, ServiceListener

class PeerListener(ServiceListener):
    def __init__(self):
        self.peers = []

    def add_service(self, zeroconf, service_type, name):
        info = zeroconf.get_service_info(service_type, name)
        if info and info.addresses:
            ip = socket.inet_ntoa(info.addresses[0])
            port = info.port
            print(f"➡️ Discovered: {name} at {ip}:{port}")
            self.peers.append({
                "name": name,
                "ip": ip,
                "port": port
            })

class PeerListener(ServiceListener):
    def __init__(self):
        self.peers = []

    def add_service(self, zeroconf, service_type, name):
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

