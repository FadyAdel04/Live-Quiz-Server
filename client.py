import socket
import threading
import sys
import time

HOST = '192.168.1.18'   # Replace with your server IP
PORT = 5555
BUFFER_SIZE = 4096

# ---------------------------------
# Send network offline notice
# ---------------------------------
def send_network_offline_notice(client, server_addr):
    """Send message to the server if network goes off."""
    try:
        client.sendto("[Client Error] Network disconnected.".encode(), server_addr)
    except Exception:
        pass  # Server may already be unreachable
    finally:
        client.close()
        print("🔌 Connection closed due to network disconnection.")
        sys.exit()


# ---------------------------------
# Receive messages from server
# ---------------------------------
def receive_messages(client):
    """Continuously listen for messages from the server."""
    while True:
        try:
            message, _ = client.recvfrom(BUFFER_SIZE)
            if not message:
                print("⚠️ Disconnected from server.")
                break
            print(message.decode())
        except ConnectionResetError:
            print("❌ Connection closed by server.")
            break
        except OSError:
            print("⚠️ Network disconnected.")
            break
        except Exception as e:
            print(f"⚠️ Error receiving message: {e}")
            break


# ---------------------------------
# Main UDP Client Logic
# ---------------------------------
def main():
    """Main client logic for UDP quiz."""
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_addr = (HOST, PORT)

    print(f"✅ Connected to UDP server at {HOST}:{PORT}")
    print("💡 Type 'exit' anytime to quit.\n")

    # Start listening thread
    threading.Thread(target=receive_messages, args=(client,), daemon=True).start()

    try:
        # Initiate connection (first message to server)
        client.sendto("hello".encode(), server_addr)

        while True:
            msg = input()
            if msg.lower() == 'exit':
                print("👋 Disconnecting...")
                client.sendto("[Client Exit] User disconnected.".encode(), server_addr)
                break

            try:
                client.sendto(msg.encode(), server_addr)
            except OSError:
                print("⚠️ Network connection lost.")
                send_network_offline_notice(client, server_addr)
                break
    except KeyboardInterrupt:
        print("\n🛑 Client exiting...")
        client.sendto("[Client Exit] User interrupted.".encode(), server_addr)
    except Exception as e:
        print(f"⚠️ Error sending message: {e}")
        send_network_offline_notice(client, server_addr)
    finally:
        client.close()
        print("🔌 Connection closed.")


if __name__ == "__main__":
    main()
