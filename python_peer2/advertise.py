from zeroconf import ServiceInfo, Zeroconf
import socket
import random
import string

zeroconf_instance = None

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

def generate_random_suffix(length=4):
    """Generate a random hex string to make the service name unique"""
    return ''.join(random.choices('0123456789abcdef', k=length))

def advertise_service(name="python-peer", port=5003):
    global zeroconf_instance
    ip = get_local_ip()
    desc = {
        "address": ip,
        "discovery_port": "5000",
        "network_port": str(port)
    }

    # Add a random suffix to make the service name unique
    unique_name = f"{name}-{generate_random_suffix()}"
    service_name = f"{unique_name}._peer._tcp.local."
    info = ServiceInfo(
        "_peer._tcp.local.",
        service_name,
        addresses=[socket.inet_aton(ip)],
        port=port,
        properties=desc,
        server=f"{unique_name}.local."
    )

    zeroconf_instance = Zeroconf()
    zeroconf_instance.register_service(info)
    print(f"[Python] ✅ Advertised {service_name} on {ip}:{port}")
    return service_name

def stop_advertisement():
    if zeroconf_instance:
        zeroconf_instance.close()
        print("[Python] 🔌 Advertisement stopped")

if __name__ == "__main__":
    advertise_service()
    try:
        input("Press enter to exit...\n")
    finally:
        stop_advertisement()
