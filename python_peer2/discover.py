from zeroconf import Zeroconf, ServiceBrowser, ServiceListener, ServiceInfo
import socket

class MyListener:
    def add_service(self, zeroconf, service_type, name):
        info = zeroconf.get_service_info(service_type, name)
        if info:
            ip = socket.inet_ntoa(info.addresses[0])
            port = info.port
            print(f"➡️ Found peer: {name} at {ip}:{port}")
        else:
            print(f"❓ Service added: {name}, but no info available")

    def remove_service(self, zeroconf, service_type, name):
        print(f"❌ Service removed: {name}")

    def update_service(self, zeroconf, service_type, name):
        print(f"🔄 Service updated: {name}")

print("🔍 Browsing for _peer._tcp.local services...")

zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, "_peer._tcp.local.", listener)

input("Press enter to stop...\n")
zeroconf.close()
