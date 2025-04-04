# file_request.py
import socket
import json
import os

def test_ping(ip, port):
    with socket.create_connection((ip, port)) as sock:
        sock.send(b"PING")
        print(f"✅ Sent 'PING' to {ip}:{port}")

def request_file(ip, port, filename):
    os.makedirs("Received", exist_ok=True)

    with socket.create_connection((ip, port)) as sock:
        request = {
            "file_name": filename,
        }
        request_bytes = json.dumps(request).encode("utf-8")
        sock.send(b"F")
        sock.send(len(request_bytes).to_bytes(4, 'big'))
        sock.send(request_bytes)

        resp_type = sock.recv(1)
        if resp_type != b"F":
            print("❌ Unexpected response type")
            return

        resp_len = int.from_bytes(sock.recv(4), 'big')
        resp = json.loads(sock.recv(resp_len).decode())

        if resp.get("status") != "accepted":
            print("❌ Rejected:", resp.get("message"))
            return

        dtype = sock.recv(1)
        dlen = int.from_bytes(sock.recv(4), 'big')
        content = sock.recv(dlen)

        with open(f"Received/{filename}", 'wb') as f:
            f.write(content)

        print(f"✅ File '{filename}' received and saved to /Received/")
