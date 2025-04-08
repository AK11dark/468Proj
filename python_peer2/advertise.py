from zeroconf import ServiceInfo, Zeroconf
import socket
import secrets
import random
import string

zeroconf_instance = None

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

def generate_random_id(length=4):
    """Generate a random hex string of specified length, similar to Ruby's SecureRandom.hex"""
    return secrets.token_hex(length)

def advertise_service(port=5003):
    global zeroconf_instance
    ip = get_local_ip()
    
    # Generate a unique name with random component
    random_id = generate_random_id(4)
    name = f"python-peer-{random_id}"
    
    desc = {
        "address": ip,
        "discovery_port": "5000",
        "network_port": str(port)
    }

    service_name = f"{name}._peer._tcp.local."
    info = ServiceInfo(
        "_peer._tcp.local.",
        service_name,
        addresses=[socket.inet_aton(ip)],
        port=port,
        properties=desc,
        server=f"{name}.local."
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
