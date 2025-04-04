import socket
import json
import os

PORT = 5000
FILES_DIR = "Files"
os.makedirs(FILES_DIR, exist_ok=True)

def handle_client(conn):
    try:
        msg_type = conn.recv(1)
        data_len = int.from_bytes(conn.recv(4), 'big')
        data = conn.recv(data_len)
        request = json.loads(data.decode())
        file_name = request["file_name"]
        is_sending = request["is_sending"]

        print(f"[Python Server] 🔄 {file_name} ({'sending' if is_sending else 'requesting'})")

        if is_sending:
            # Accept incoming file
            conn.send(b"F")
            response = json.dumps({"status": "accepted"}).encode()
            conn.send(len(response).to_bytes(4, 'big'))
            conn.send(response)

            # Read file data
            dtype = conn.recv(1)
            dlen = int.from_bytes(conn.recv(4), 'big')
            content = conn.recv(dlen)

            with open(f"{FILES_DIR}/{file_name}", 'wb') as f:
                f.write(content)

            print(f"[Python Server] ✅ Saved file to Files/{file_name}")

        else:
            # Respond and send file if exists
            filepath = f"{FILES_DIR}/{file_name}"
            if os.path.exists(filepath):
                conn.send(b"F")
                response = json.dumps({"status": "accepted"}).encode()
                conn.send(len(response).to_bytes(4, 'big'))
                conn.send(response)

                with open(filepath, 'rb') as f:
                    content = f.read()
                conn.send(b"D")
                conn.send(len(content).to_bytes(4, 'big'))
                conn.send(content)

                print(f"[Python Server] 📤 Sent file '{file_name}'")
            else:
                conn.send(b"F")
                error = json.dumps({"status": "rejected", "message": "File not found"}).encode()
                conn.send(len(error).to_bytes(4, 'big'))
                conn.send(error)
                print(f"[Python Server] ❌ File not found: {file_name}")

    except Exception as e:
        print(f"[Python Server] ❌ Error: {e}")
    finally:
        conn.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', PORT))
    server.listen(5)
    print(f"[Python Server] 🚀 Listening on port {PORT}...")

    while True:
        conn, _ = server.accept()
        handle_client(conn)

if __name__ == "__main__":
    main()
