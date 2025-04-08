import socket
import time
from zeroconf import Zeroconf, ServiceBrowser, ServiceListener


class PeerListener(ServiceListener):
    def __init__(self):
        self.peers = []
        # Get the local IP to filter out self in discovery
        self.local_ip = self._get_local_ip()
        print(f"Local IP: {self.local_ip}")

    def _get_local_ip(self):
        """Get the local IP address for filtering out self in discovery"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            # Fallback to loopback address if unable to determine
            return "127.0.0.1"

    def add_service(self, zeroconf, service_type, name):
        info = zeroconf.get_service_info(service_type, name)
        if info and info.addresses:
            ip = socket.inet_ntoa(info.addresses[0])
            
            # Skip if this is the local machine (ourselves)
            if ip == self.local_ip:
                print(f"Skipping local service: {name} @ {ip}")
                return
                
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

