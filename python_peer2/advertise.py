from zeroconf import ServiceInfo, Zeroconf
import socket

zeroconf_instance = None

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

def advertise_service(name="python-peer", port=5001):
    global zeroconf_instance
    ip = get_local_ip()
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
