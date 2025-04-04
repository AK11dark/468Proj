import socket
import json
import os

# Function to start the Python file server
def start_file_server(host='0.0.0.0', port=5003):  # Change port to 5002
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)

    print(f"[Python File Server] Listening on {host}:{port}...")

    while True:
        client_socket, client_address = server.accept()
        print(f"[Python File Server] Connection from {client_address}")

        try:
            msg_type = client_socket.recv(1)
            if msg_type == b"F":  # File request
                data_len = int.from_bytes(client_socket.recv(4), 'big')
                data = client_socket.recv(data_len)
                request = json.loads(data.decode('utf-8'))

                file_name = request.get("file_name")
                print(f"[Python File Server] 📥 Incoming request for file '{file_name}'")

                file_path = os.path.join("Files", file_name)
                if os.path.exists(file_path):
                    with open(file_path, 'rb') as file:
                        file_content = file.read()

                    # Step 1: Send acknowledgment
                    response = {"status": "accepted"}
                    client_socket.send(b"F")  # Acknowledge the file request
                    client_socket.send(len(json.dumps(response).encode('utf-8')).to_bytes(4, 'big'))
                    client_socket.send(json.dumps(response).encode('utf-8'))

                    # Step 2: Send the file content
                    client_socket.send(b"D")  # Send file data
                    client_socket.send(len(file_content).to_bytes(4, 'big'))
                    client_socket.send(file_content)
                    print(f"[Python File Server] ✅ Sent file '{file_name}'")
                else:
                    response = {"status": "rejected", "message": "File not found"}
                    client_socket.send(b"F")  # Acknowledge the file request
                    client_socket.send(len(json.dumps(response).encode('utf-8')).to_bytes(4, 'big'))
                    client_socket.send(json.dumps(response).encode('utf-8'))
                    print(f"[Python File Server] ❌ File not found: {file_name}")

            else:
                print(f"[Python File Server] ❓ Unknown message type: {msg_type}")

        except Exception as e:
            print(f"[Python File Server] ❌ Error: {e}")
        finally:
            client_socket.close()

# To start the server, call the function:
if __name__ == "__main__":
    start_file_server(host='0.0.0.0', port=5003)  # Use a different port for Python
