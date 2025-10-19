import socket
import threading
import sys

HOST = '192.168.1.18'  # Replace with your server IP
PORT = 8080


def receive_messages(client):
    """Listen for messages from the server."""
    while True:
        try:
            message = client.recv(1024).decode()
            if not message:
                print("⚠️ Disconnected from server.")
                break
            print(message)
        except ConnectionResetError:
            print("❌ Connection closed by server.")
            break
        except Exception as e:
            print(f"⚠️ Error receiving message: {e}")
            break
    client.close()
    sys.exit()


def main():
    """Main client logic."""
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client.connect((HOST, PORT))
        print(f"✅ Connected to server at {HOST}:{PORT}")
    except ConnectionRefusedError:
        print("❌ Connection failed: Server is not running or unreachable.")
        return
    except TimeoutError:
        print("⏰ Connection timed out. Try again later.")
        return
    except Exception as e:
        print(f"⚠️ Unexpected connection error: {e}")
        return

    threading.Thread(target=receive_messages, args=(client,), daemon=True).start()

    try:
        while True:
            msg = input()
            if msg.lower() == 'exit':
                print("👋 Disconnecting...")
                break
            client.sendall(msg.encode())
    except KeyboardInterrupt:
        print("\n🛑 Client exiting...")
    except BrokenPipeError:
        print("❌ Server connection lost.")
    except Exception as e:
        print(f"⚠️ Error sending message: {e}")
    finally:
        client.close()
        print("🔌 Connection closed.")


if __name__ == "__main__":
    main()
