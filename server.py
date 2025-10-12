import socket
import threading
import json
import time

HOST = '127.0.0.1'
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

    for _ in range(3):  # Allow up to 3 login attempts
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
    for conn in clients.values():
        try:
            conn.sendall(message.encode())
        except:
            pass


def handle_client(conn, addr, username):
    conn.sendall("Welcome to the quiz!\n".encode())
    time.sleep(1)

    # Load questions
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
            conn.sendall(" Time’s up!\n".encode())
            answer = None

        if answer == q['answer']:
            score += 1
            conn.sendall("✅ Correct!\n".encode())
        else:
            conn.sendall(f"❌ Wrong! Correct answer: {q['answer']}\n".encode())

    with lock:
        scores[username] = score

    # Send final score
    conn.sendall(f"\n Your total score: {score}\n".encode())

    # Send leaderboard
    leaderboard = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    leaderboard_text = "\n Leaderboard:\n" + "\n".join([f"{u}: {s}" for u, s in leaderboard])
    broadcast(leaderboard_text)

    conn.close()


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()

    print(f"Server started on {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        username = authenticate_user(conn)
        if not username:
            continue 

        clients[username] = conn
        print(f"{username} connected from {addr}")
        threading.Thread(target=handle_client, args=(conn, addr, username)).start()


if __name__ == "__main__":
    start_server()
