import socket
import json
import threading
import os

def handle_client(conn, addr):
    print(f"Connection from {addr}")
    data = conn.recv(1024).decode()
    message = json.loads(data)

    if message["type"] == "file_request":
        filename = message["filename"]
        print(f"Peer requested file: {filename}")

        consent = input("Allow transfer? (y/n): ").strip().lower()
        if consent == "y" and os.path.exists(filename):
            response = json.dumps({ "status": "accepted" })
            conn.sendall(response.encode())
            with open(filename, "rb") as f:
                while chunk := f.read(1024):
                    conn.sendall(chunk)
            print("File sent.")
        else:
            response = json.dumps({ "status": "denied" })
            conn.sendall(response.encode())

    conn.close()

def start_server(port=5000):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("", port))
    server.listen()
    print(f"Listening on port {port}...")

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

start_server()
