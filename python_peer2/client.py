import socket
import json
import os

def send_file_request(ip, port, file_name, is_sending):
    sock = socket.create_connection((ip, port))
    try:
        request = {
            "file_name": file_name,
            "is_sending": is_sending
        }
        request_json = json.dumps(request).encode('utf-8')

        # Send message type and payload
        sock.send(b"F")
        sock.send(len(request_json).to_bytes(4, 'big'))
        sock.send(request_json)

        # Read response
        resp_type = sock.recv(1)
        resp_len = int.from_bytes(sock.recv(4), 'big')
        resp = json.loads(sock.recv(resp_len).decode())

        if resp.get("status") == "accepted":
            if is_sending:
                with open(f"Files/{file_name}", 'rb') as f:
                    content = f.read()
                sock.send(b"D")
                sock.send(len(content).to_bytes(4, 'big'))
                sock.send(content)
                print("✅ File sent.")
            else:
                dtype = sock.recv(1)
                dlen = int.from_bytes(sock.recv(4), 'big')
                data = sock.recv(dlen)
                os.makedirs("Received", exist_ok=True)
                with open(f"Received/{file_name}", 'wb') as f:
                    f.write(data)
                print("✅ File received.")
        else:
            print("❌ Request rejected:", resp.get("message"))
    finally:
        sock.close()

# Replace with actual discovered IP and port from your Ruby peer
RUBY_IP = "10.0.6.205"  # or the actual IP discovered via Zeroconf
RUBY_PORT = 5001
FILE_NAME = "needfromruby.txt"

send_file_request(RUBY_IP, RUBY_PORT, FILE_NAME, is_sending=False)
