import socket
import threading
import json
import time
import traceback  # for detailed error logging

HOST = '0.0.0.0'
PORT = 8080
QUESTION_TIME = 15

clients = {}
scores = {}
lock = threading.Lock()


def load_users():
    """Load registered users from users.json"""
    try:
        with open('users.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print("❌ Error: users.json not found.")
        return {}
    except json.JSONDecodeError:
        print("❌ Error: users.json file is not valid JSON.")
        return {}


def authenticate_user(conn):
    """Ask for username/password and validate."""
    users = load_users()

    for _ in range(3):
        try:
            conn.sendall("Enter your username: ".encode())
            username = conn.recv(1024).decode().strip()

            conn.sendall("Enter your password: ".encode())
            password = conn.recv(1024).decode().strip()
        except Exception as e:
            print(f"⚠️ Connection error during authentication: {e}")
            return None

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
        except Exception:
            # Remove disconnected clients
            for user, c in clients.items():
                if c == conn:
                    print(f"⚠️ Disconnected client removed: {user}")
                    del clients[user]
                    break


def handle_client(conn, addr, username):
    """Handle individual client session."""
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
            except Exception:
                conn.sendall("⚠️ Error receiving your answer.\n".encode())
                answer = None

            if answer == q['answer']:
                score += 1
                conn.sendall("✅ Correct!\n".encode())
            else:
                conn.sendall(f"❌ Wrong! Correct answer: {q['answer']}\n".encode())

        with lock:
            scores[username] = score

        conn.sendall(f"\n🏁 Your total score: {score}\n".encode())

        # Send updated leaderboard
        leaderboard = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        leaderboard_text = "\n🏆 Leaderboard:\n" + "\n".join([f"{u}: {s}" for u, s in leaderboard])
        broadcast(leaderboard_text)

    except Exception as e:
        print(f"❌ Error handling client {username}: {e}")
        traceback.print_exc()
    finally:
        conn.close()
        with lock:
            if username in clients:
                del clients[username]
        print(f"🔌 {username} disconnected.")


def start_server():
    """Start the TCP quiz server."""
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((HOST, PORT))
        server.listen()
        print(f"✅ Server started on {HOST}:{PORT}")
    except Exception as e:
        print(f"❌ Failed to start server: {e}")
        return

    while True:
        try:
            conn, addr = server.accept()
            print(f"📥 Connection from {addr}")
            username = authenticate_user(conn)
            if not username:
                continue

            clients[username] = conn
            print(f"👤 {username} connected.")
            threading.Thread(target=handle_client, args=(conn, addr, username), daemon=True).start()

        except KeyboardInterrupt:
            print("\n🛑 Server shutting down...")
            break
        except Exception as e:
            print(f"⚠️ Unexpected server error: {e}")
            traceback.print_exc()

    server.close()


if __name__ == "__main__":
    start_server()
