import socket
import threading
import sys
import time

SERVER_IP = '192.168.1.11'
SERVER_PORT = 5555
BUFFER_SIZE = 4096

def receive_messages(client):
    """Listen for incoming messages from server."""
    while True:
        try:
            data, _ = client.recvfrom(BUFFER_SIZE)
            message = data.decode()
            print(message)
        except Exception as e:
            print(f"⚠️ Connection error: {e}")
            break

def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_addr = (SERVER_IP, SERVER_PORT)

    try:
        # Initiate connection
        client.sendto("HELLO".encode(), server_addr)
        threading.Thread(target=receive_messages, args=(client,), daemon=True).start()

        while True:
            msg = input()
            if msg.lower() == "exit":
                print("👋 Exiting quiz. Goodbye!")
                break
            client.sendto(msg.encode(), server_addr)

    except KeyboardInterrupt:
        print("\n👋 Client closed manually.")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
    finally:
        client.close()
        sys.exit()

if __name__ == "__main__":
    main()
