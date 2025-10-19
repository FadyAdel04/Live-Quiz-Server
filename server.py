import socket
import threading
import json
import time
import traceback  # for detailed error logs

HOST = '0.0.0.0'
PORT = 5555
QUESTION_TIME = 15

clients = {}
scores = {}
lock = threading.Lock()


def load_users():
    """Load registered users from users.json"""
    with open('users.json', 'r') as f:
        return json.load(f)


def authenticate_user(conn):
    """Ask for username/password and validate."""
    users = load_users()

    for _ in range(3):
        conn.sendall("Enter your username: ".encode())
        username = conn.recv(1024).decode().strip()

        conn.sendall("Enter your password: ".encode())
        password = conn.recv(1024).decode().strip()

        if username in users and users[username] == password:
            conn.sendall(f"✅ Login successful! Welcome {username}.\n".encode())
            return username
        else:
            conn.sendall("❌ Invalid credentials. Try again.\n".encode())

    conn.sendall("🚫 Too many failed attempts. Connection closed.\n".encode())
    conn.close()
    return None


def broadcast(message):
    """Send a message to all connected clients."""
    for conn in list(clients.values()):
        try:
            conn.sendall(message.encode())
        except:
            pass


def handle_client(conn, addr, username):
    try:
        conn.sendall("Welcome to the quiz!\n".encode())
        time.sleep(1)

        with open('questions.json', 'r') as f:
            questions = json.load(f)

        score = 0
        for q in questions:
            question_text = (
                f"\n{q['question']}\n"
                + "\n".join(q["options"])
                + f"\nYou have {QUESTION_TIME} seconds. Enter A/B/C/D: "
            )
            conn.sendall(question_text.encode())

            conn.settimeout(QUESTION_TIME)
            try:
                answer = conn.recv(1024).decode().strip().upper()
            except socket.timeout:
                conn.sendall("⏰ Time’s up!\n".encode())
                answer = None
            except (ConnectionResetError, ConnectionAbortedError):
                print(f"[!] {username} disconnected unexpectedly.")
                break

            if answer == q['answer']:
                score += 1
                conn.sendall("✅ Correct!\n".encode())
            else:
                conn.sendall(f"❌ Wrong! Correct answer: {q['answer']}\n".encode())

        with lock:
            scores[username] = score

        conn.sendall(f"\nYour total score: {score}\n".encode())

        leaderboard = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        leaderboard_text = "\nLeaderboard:\n" + "\n".join([f"{u}: {s}" for u, s in leaderboard])
        broadcast(leaderboard_text)

    except Exception as e:
        print(f"[ERROR] Error handling {username} from {addr}: {e}")
        traceback.print_exc()  # print full error details for debugging
        try:
            conn.sendall("⚠️ Something went wrong on the server. Please try again later.\n".encode())
        except:
            pass
    finally:
        conn.close()
        with lock:
            if username in clients:
                del clients[username]
        print(f"❌ Connection closed for {username}")


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((HOST, PORT))
        server.listen()
        print(f"✅ Server started on {HOST}:{PORT}")

        while True:
            try:
                conn, addr = server.accept()
                print(f"[NEW CONNECTION] {addr}")

                username = authenticate_user(conn)
                if not username:
                    continue

                clients[username] = conn
                print(f"{username} connected from {addr}")

                threading.Thread(target=handle_client, args=(conn, addr, username), daemon=True).start()

            except Exception as e:
                print(f"[SERVER ERROR] {e}")
                traceback.print_exc()
    except Exception as e:
        print(f"❌ Failed to start server: {e}")
        traceback.print_exc()
    finally:
        server.close()
        print("🛑 Server stopped.")


if __name__ == "__main__":
    start_server()
