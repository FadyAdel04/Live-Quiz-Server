#tempCodeRunnerFile.py
import socket
import json
import threading
import time
import traceback

# -------------------------------
# UDP Server Configuration
# -------------------------------
HOST = '0.0.0.0'
PORT = 5555
BUFFER_SIZE = 4096
QUESTION_TIME = 15

clients = {}   # username -> (address)
scores = {}
lock = threading.Lock()


# -------------------------------
# Load Users from users.json
# -------------------------------
def load_users():
    """Load registered users from users.json"""
    try:
        with open('users.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print("❌ Error: users.json not found.")
        return {}
    except json.JSONDecodeError:
        print("❌ Error: users.json is not valid JSON.")
        return {}


# -------------------------------
# Helper: Send data via UDP
# -------------------------------
def send_udp_message(sock, message, addr):
    """Send message to specific client address"""
    try:
        sock.sendto(message.encode(), addr)
    except Exception as e:
        print(f"⚠️ Error sending message: {e}")


# -------------------------------
# Error log message after 3 seconds
# -------------------------------
def send_error_with_delay(sock, addr, message):
    """Wait 3 seconds then send error log message to client."""
    def delayed_send():
        time.sleep(3)
        try:
            sock.sendto(f"\n⚠️ Error log: {message}\n".encode(), addr)
        except:
            pass
    threading.Thread(target=delayed_send, daemon=True).start()


# -------------------------------
# Authentication (Username & Password)
# -------------------------------
def authenticate_user(sock, addr, users):
    """Handle user login via UDP communication."""
    try:
        send_udp_message(sock, "Enter your username:", addr)
        username, _ = sock.recvfrom(BUFFER_SIZE)
        username = username.decode().strip()

        send_udp_message(sock, "Enter your password:", addr)
        password, _ = sock.recvfrom(BUFFER_SIZE)
        password = password.decode().strip()

        if username in users and users[username] == password:
            send_udp_message(sock, f"✅ Login successful! Welcome {username}.", addr)
            return username
        else:
            send_udp_message(sock, "❌ Invalid credentials. Connection refused.", addr)
            return None
    except Exception as e:
        print(f"⚠️ Authentication error: {e}")
        send_error_with_delay(sock, addr, f"Authentication error: {e}")
        return None


# -------------------------------
# Broadcast Message to All Clients
# -------------------------------
def broadcast(sock, message):
    """Send message to all connected UDP clients"""
    for user, address in list(clients.items()):
        try:
            sock.sendto(message.encode(), address)
        except Exception:
            print(f"⚠️ Failed to send message to {user}")


# -------------------------------
# Handle Each Player Session
# -------------------------------
def handle_client(sock, username, addr):
    """Main quiz logic for a single user"""
    try:
        send_udp_message(sock, "Welcome to the UDP Quiz!\n", addr)
        time.sleep(1)

        # Load quiz questions
        with open('questions.json', 'r') as f:
            questions = json.load(f)

        score = 0
        for q in questions:
            question_text = (
                f"\n{q['question']}\n"
                + "\n".join(q["options"])
                + f"\nYou have {QUESTION_TIME} seconds. Enter A/B/C/D:"
            )
            send_udp_message(sock, question_text, addr)

            sock.settimeout(QUESTION_TIME)
            try:
                answer, _ = sock.recvfrom(BUFFER_SIZE)
                answer = answer.decode().strip().upper()
            except socket.timeout:
                send_udp_message(sock, "⏰ Time’s up!", addr)
                answer = None
            except Exception as e:
                send_udp_message(sock, "⚠️ Error receiving your answer.", addr)
                send_error_with_delay(sock, addr, f"Error receiving answer: {e}")
                answer = None

            if answer == q['answer']:
                score += 1
                send_udp_message(sock, "✅ Correct!", addr)
            else:
                send_udp_message(sock, f"❌ Wrong! Correct answer: {q['answer']}", addr)

        # Update scores
        with lock:
            scores[username] = score

        send_udp_message(sock, f"\n🏁 Your total score: {score}", addr)

        # Send leaderboard to all
        leaderboard = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        leaderboard_text = "\n🏆 Leaderboard:\n" + "\n".join([f"{u}: {s}" for u, s in leaderboard])
        broadcast(sock, leaderboard_text)

    except Exception as e:
        print(f"❌ Error handling client {username}: {e}")
        traceback.print_exc()
        send_error_with_delay(sock, addr, f"Server error: {e}")
    finally:
        with lock:
            if username in clients:
                del clients[username]
        print(f"🔌 {username} disconnected.")


# -------------------------------
# Start UDP Quiz Server
# -------------------------------
def start_server():
    """Start the UDP-based quiz server"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((HOST, PORT))
        print(f"✅ UDP Server started on {HOST}:{PORT}")
    except Exception as e:
        print(f"❌ Failed to start UDP server: {e}")
        return
