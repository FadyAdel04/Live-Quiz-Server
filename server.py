import socket
import json
import threading
import time
import traceback

HOST = '0.0.0.0'
PORT = 5555
BUFFER_SIZE = 4096
QUESTION_TIME = 15

clients = {}   # username -> (address)
scores = {}
lock = threading.Lock()

def load_users():
    """Load registered users from users.json"""
    try:
        with open('users.json', 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] Loading users.json failed: {e}")
        return {}

def send_message(server, message, addr):
    """Safely send a message to a UDP client."""
    try:
        server.sendto(message.encode(), addr)
    except Exception as e:
        print(f"[SEND ERROR] Could not send to {addr}: {e}")

def authenticate_user(server, addr):
    """Ask for username/password and validate."""
    users = load_users()

    for _ in range(3):
        send_message(server, "Enter your username: ", addr)
        try:
            username, _ = server.recvfrom(BUFFER_SIZE)
            username = username.decode().strip()

            send_message(server, "Enter your password: ", addr)
            password, _ = server.recvfrom(BUFFER_SIZE)
            password = password.decode().strip()

            if username in users and users[username] == password:
                send_message(server, f"✅ Login successful! Welcome {username}.", addr)
                return username
            else:
                send_message(server, "❌ Invalid credentials. Try again.", addr)
        except Exception as e:
            send_message(server, f"⚠️ Error during authentication: {e}", addr)
            return None

    send_message(server, "🚫 Too many failed attempts. Connection closed.", addr)
    return None

def broadcast(server, message):
    """Broadcast message to all connected clients."""
    for user, addr in list(clients.items()):
        send_message(server, message, addr)

def handle_quiz(server, username, addr):
    """Send quiz questions and calculate score."""
    try:
        with open('questions.json', 'r') as f:
            questions = json.load(f)

        score = 0
        for q in questions:
            question_text = (
                f"\n{q['question']}\n"
                + "\n".join(q['options'])
                + f"\nYou have {QUESTION_TIME} seconds. Enter A/B/C/D: "
            )
            send_message(server, question_text, addr)

            server.settimeout(QUESTION_TIME)
            try:
                data, _ = server.recvfrom(BUFFER_SIZE)
                answer = data.decode().strip().upper()
            except socket.timeout:
                send_message(server, "⏰ Time’s up!", addr)
                answer = None
            except Exception as e:
                send_message(server, f"⚠️ Error receiving answer: {e}", addr)
                continue

            if answer == q['answer']:
                score += 1
                send_message(server, "✅ Correct!", addr)
            else:
                send_message(server, f"❌ Wrong! Correct answer: {q['answer']}", addr)

        with lock:
            scores[username] = score

        send_message(server, f"\nYour total score: {score}", addr)

        leaderboard = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        leaderboard_text = "\n🏆 Leaderboard:\n" + "\n".join([f"{u}: {s}" for u, s in leaderboard])
        broadcast(server, leaderboard_text)

    except Exception as e:
        print(f"[ERROR] Quiz handling for {username}: {e}")
        traceback.print_exc()
        send_message(server, "⚠️ Internal server error during quiz.", addr)

def start_server():
    """Start UDP server and handle incoming clients."""
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((HOST, PORT))
    print(f"✅ UDP Server started on {HOST}:{PORT}")

    try:
        while True:
            try:
                data, addr = server.recvfrom(BUFFER_SIZE)
                message = data.decode().strip()

                # "HELLO" acts as connection initiation
                if message == "HELLO":
                    send_message(server, "Welcome! Please log in.", addr)
                    username = authenticate_user(server, addr)
                    if username:
                        with lock:
                            clients[username] = addr
                        print(f"[CONNECTED] {username} from {addr}")
                        threading.Thread(target=handle_quiz, args=(server, username, addr), daemon=True).start()
                    continue
            except Exception as e:
                print(f"[SERVER ERROR] {e}")
                traceback.print_exc()
    except KeyboardInterrupt:
        print("\n🛑 Server stopped manually.")
    finally:
        server.close()

if __name__ == "__main__":
    start_server()
