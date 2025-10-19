import socket
import threading
import sys
import time

HOST = '192.168.1.11'
PORT = 5555

def receive_messages(client):
    while True:
        try:
            message = client.recv(1024).decode()
            if not message:
                print("⚠️ Server disconnected. Please try again later.")
                break
            print(message)
        except (ConnectionResetError, ConnectionAbortedError):
            print("⚠️ Connection lost. Server might be offline.")
            break
        except Exception as e:
            print(f"⚠️ Unexpected error: {e}")
            break
    client.close()
    sys.exit()


def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((HOST, PORT))
    except Exception as e:
        print("❌ Connection failed! Unable to reach the server.")
        print(f"[Technical Error] {e}")
        time.sleep(2)
        return

    threading.Thread(target=receive_messages, args=(client,), daemon=True).start()

    try:
        while True:
            msg = input()
            if msg.lower() == 'exit':
                print("👋 Exiting the quiz. Goodbye!")
                break
            client.sendall(msg.encode())
    except (KeyboardInterrupt, EOFError):
        print("\n👋 Client closed manually.")
    except Exception as e:
        print(f"⚠️ Unexpected error: {e}")
    finally:
        client.close()


if __name__ == "__main__":
    main()
