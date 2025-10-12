import socket
import threading

HOST = '127.0.0.1'
PORT = 5555

def receive_messages(client):
    while True:
        try:
            message = client.recv(1024).decode()
            if not message:
                break
            print(message)
        except:
            break

def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))

    threading.Thread(target=receive_messages, args=(client,), daemon=True).start()

    while True:
        msg = input()
        if msg.lower() == 'exit':
            break
        client.sendall(msg.encode())

    client.close()

if __name__ == "__main__":
    main()
