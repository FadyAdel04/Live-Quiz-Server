import socket
import json
import threading
import time
import traceback
import logging
from datetime import datetime
from typing import Dict, Tuple, Optional

# -------------------------------
# Server Configuration & Logging
# -------------------------------
HOST = '0.0.0.0'
PORT = 8080
BUFFER_SIZE = 4096
QUESTION_TIME = 15
ACK_TIMEOUT = 5
MAX_RETRIES = 3

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class QuizServer:
    def __init__(self):
        self.clients: Dict[str, Tuple[str, int]] = {}  # username -> (ip, port)
        self.scores: Dict[str, int] = {}
        self.client_states: Dict[str, Dict] = {}  # Track client state
        self.lock = threading.Lock()
        self.running = True
        self.sock = None
        
    def load_users(self) -> Dict[str, str]:
        """Load registered users from users.json with error handling"""
        try:
            with open('users.json', 'r') as f:
                users = json.load(f)
                logger.info(f"Loaded {len(users)} users from users.json")
                return users
        except FileNotFoundError:
            logger.error("users.json not found. Using empty user database.")
            return {}
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in users.json: {e}")
            return {}
        except Exception as e:
            logger.error(f"Unexpected error loading users: {e}")
            return {}

    def load_questions(self) -> list:
        """Load quiz questions with error handling"""
        try:
            with open('questions.json', 'r') as f:
                questions = json.load(f)
                logger.info(f"Loaded {len(questions)} questions")
                return questions
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error(f"Error loading questions: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error loading questions: {e}")
            return []

    def send_with_retry(self, message: str, addr: Tuple[str, int], max_retries: int = MAX_RETRIES) -> bool:
        """Send message with retry mechanism for reliability"""
        for attempt in range(max_retries):
            try:
                self.sock.sendto(message.encode(), addr)
                
                # Wait for ACK for critical messages
                if message.startswith(("AUTH_REQ", "QUESTION", "SCORE_UPDATE")):
                    return self.wait_for_ack(addr, f"ACK_{hash(message)}")
                return True
                
            except socket.error as e:
                logger.warning(f"Send attempt {attempt + 1} failed for {addr}: {e}")
                if attempt == max_retries - 1:
                    logger.error(f"Failed to send message to {addr} after {max_retries} attempts")
                    return False
                time.sleep(1)  # Wait before retry
        return False

    def wait_for_ack(self, addr: Tuple[str, int], expected_ack: str, timeout: int = ACK_TIMEOUT) -> bool:
        """Wait for ACK confirmation from client"""
        original_timeout = self.sock.gettimeout()
        try:
            self.sock.settimeout(timeout)
            data, client_addr = self.sock.recvfrom(BUFFER_SIZE)
            if client_addr == addr and data.decode().strip() == expected_ack:
                return True
        except socket.timeout:
            logger.warning(f"ACK timeout from {addr} for {expected_ack}")
        except Exception as e:
            logger.warning(f"Error waiting for ACK from {addr}: {e}")
        finally:
            self.sock.settimeout(original_timeout)
        return False

    def authenticate_user(self, addr: Tuple[str, int], users: Dict[str, str]) -> Optional[str]:
        """Handle user authentication with ACK confirmation"""
        try:
            # Send authentication request with unique ID
            auth_id = f"AUTH_REQ_{int(time.time())}"
            if not self.send_with_retry(auth_id, addr):
                logger.warning(f"Authentication request failed for {addr}")
                return None

            # Get username
            self.sock.settimeout(30)  # 30 second timeout for authentication
            username_data, client_addr = self.sock.recvfrom(BUFFER_SIZE)
            if client_addr != addr:
                logger.warning(f"Unexpected client during auth: {client_addr}")
                return None
                
            username = username_data.decode().strip()
            self.send_with_retry(f"ACK_USERNAME_{username}", addr)

            # Get password
            password_data, client_addr = self.sock.recvfrom(BUFFER_SIZE)
            if client_addr != addr:
                return None
                
            password = password_data.decode().strip()

            # Validate credentials
            if username in users and users[username] == password:
                auth_success = f"AUTH_SUCCESS_{username}"
                if self.send_with_retry(auth_success, addr):
                    logger.info(f"User {username} authenticated from {addr}")
                    return username
            else:
                self.send_with_retry("AUTH_FAILED", addr)
                logger.warning(f"Failed authentication attempt for {username} from {addr}")
                return None

        except socket.timeout:
            logger.warning(f"Authentication timeout for {addr}")
            self.send_with_retry("AUTH_TIMEOUT", addr)
        except Exception as e:
            logger.error(f"Authentication error for {addr}: {e}")
            self.send_with_retry("AUTH_ERROR", addr)
        finally:
            self.sock.settimeout(None)  # Reset to blocking mode
        return None

    def broadcast(self, message: str, exclude_addr: Tuple[str, int] = None):
        """Broadcast message to all connected clients except specified address"""
        failed_clients = []
        with self.lock:
            clients_copy = self.clients.copy()
        
        for username, addr in clients_copy.items():
            if exclude_addr and addr == exclude_addr:
                continue
            if not self.send_with_retry(message, addr):
                logger.warning(f"Broadcast failed for {username} at {addr}")
                failed_clients.append(username)
        
        # Clean up failed clients
        if failed_clients:
            with self.lock:
                for username in failed_clients:
                    if username in self.clients:
                        del self.clients[username]
                    if username in self.client_states:
                        del self.client_states[username]

    def handle_client(self, username: str, addr: Tuple[str, int]):
        """Main quiz logic for a single client with comprehensive error handling"""
        try:
            logger.info(f"Starting quiz session for {username} at {addr}")
            
            # Initialize client state
            with self.lock:
                self.client_states[username] = {
                    'current_question': 0,
                    'score': 0,
                    'connected': True,
                    'last_activity': time.time()
                }

            # Send welcome message
            welcome_msg = f"Welcome to the UDP Quiz, {username}!\n"
            if not self.send_with_retry(welcome_msg, addr):
                raise ConnectionError("Failed to send welcome message")

            # Load questions
            questions = self.load_questions()
            if not questions:
                self.send_with_retry("❌ Server error: No questions available.", addr)
                return

            # Quiz loop
            for i, question in enumerate(questions):
                with self.lock:
                    self.client_states[username]['current_question'] = i
                
                # Format question
                question_text = (
                    f"\nQuestion {i+1}/{len(questions)}:\n"
                    f"{question['question']}\n"
                    + "\n".join(question["options"])
                    + f"\n\nYou have {QUESTION_TIME} seconds. Enter A/B/C/D:"
                )

                # Send question with retry
                if not self.send_with_retry(f"QUESTION_{i}_{question_text}", addr):
                    logger.warning(f"Failed to send question to {username}")
                    break

                # Wait for answer with timeout
                self.sock.settimeout(QUESTION_TIME)
                try:
                    answer_data, client_addr = self.sock.recvfrom(BUFFER_SIZE)
                    if client_addr != addr:
                        continue
                    
                    answer = answer_data.decode().strip().upper()
                    self.send_with_retry(f"ACK_ANSWER_{answer}", addr)

                    # Validate answer
                    if answer == question['answer']:
                        with self.lock:
                            self.client_states[username]['score'] += 1
                        self.send_with_retry("✅ Correct!", addr)
                    else:
                        self.send_with_retry(f"❌ Wrong! Correct answer: {question['answer']}", addr)

                except socket.timeout:
                    self.send_with_retry("⏰ Time's up!", addr)
                except Exception as e:
                    logger.warning(f"Error receiving answer from {username}: {e}")
                    break

                # Update last activity
                with self.lock:
                    self.client_states[username]['last_activity'] = time.time()

            # Calculate final score
            with self.lock:
                final_score = self.client_states[username].get('score', 0)
                self.scores[username] = final_score

            # Send final score
            self.send_with_retry(f"\n🏁 Quiz completed! Your final score: {final_score}/{len(questions)}", addr)

            # Broadcast leaderboard
            self.broadcast_leaderboard()

        except Exception as e:
            logger.error(f"Error handling client {username}: {e}")
            logger.debug(traceback.format_exc())
            try:
                self.send_with_retry("❌ An error occurred during the quiz.", addr)
            except:
                pass
        finally:
            self.cleanup_client(username)
            logger.info(f"Quiz session ended for {username}")

    def broadcast_leaderboard(self):
        """Broadcast updated leaderboard to all clients"""
        with self.lock:
            if not self.scores:
                return
                
            leaderboard = sorted(self.scores.items(), key=lambda x: x[1], reverse=True)
            leaderboard_text = "\n🏆 Current Leaderboard:\n" + "\n".join(
                [f"{i+1}. {user}: {score}" for i, (user, score) in enumerate(leaderboard)]
            )
        
        self.broadcast(leaderboard_text)

    def cleanup_client(self, username: str):
        """Clean up client resources"""
        with self.lock:
            if username in self.clients:
                del self.clients[username]
            if username in self.client_states:
                del self.client_states[username]
            logger.info(f"Cleaned up resources for {username}")

    def connection_heartbeat(self):
        """Monitor client connections and clean up inactive ones"""
        while self.running:
            time.sleep(60)  # Check every minute
            current_time = time.time()
            disconnected_clients = []
            
            with self.lock:
                for username, state in self.client_states.items():
                    if current_time - state['last_activity'] > 120:  # 2 minutes inactivity
                        disconnected_clients.append(username)
            
            for username in disconnected_clients:
                logger.warning(f"Client {username} disconnected due to inactivity")
                self.cleanup_client(username)

    def start_server(self):
        """Start the UDP quiz server"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind((HOST, PORT))
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            logger.info(f"✅ UDP Quiz Server started on {HOST}:{PORT}")
            logger.info("Server is ready to accept connections...")

            users = self.load_users()
            
            # Start heartbeat thread
            heartbeat_thread = threading.Thread(target=self.connection_heartbeat, daemon=True)
            heartbeat_thread.start()

            while self.running:
                try:
                    data, addr = self.sock.recvfrom(BUFFER_SIZE)
                    message = data.decode().strip()

                    # Handle ACK messages
                    if message.startswith("ACK_"):
                        continue

                    # Handle new connections
                    if message == "hello" and addr not in self.clients.values():
                        logger.info(f"New connection attempt from {addr}")
                        
                        # Check max clients
                        with self.lock:
                            if len(self.clients) >= 50:  # Reasonable limit
                                self.send_with_retry("❌ Server is full. Try again later.", addr)
                                continue
                        
                        # Authenticate in separate thread
                        auth_thread = threading.Thread(
                            target=self.handle_authentication,
                            args=(addr, users),
                            daemon=True
                        )
                        auth_thread.start()

                except KeyboardInterrupt:
                    logger.info("Server shutdown initiated by administrator")
                    self.running = False
                    break
                except Exception as e:
                    logger.error(f"Unexpected error in main loop: {e}")
                    logger.debug(traceback.format_exc())

        except Exception as e:
            logger.critical(f"Failed to start server: {e}")
        finally:
            if self.sock:
                self.sock.close()
            logger.info("Server shutdown complete")

    def handle_authentication(self, addr: Tuple[str, int], users: Dict[str, str]):
        """Handle client authentication in separate thread"""
        username = self.authenticate_user(addr, users)
        if username:
            with self.lock:
                self.clients[username] = addr
            # Start quiz session
            quiz_thread = threading.Thread(
                target=self.handle_client,
                args=(username, addr),
                daemon=True
            )
            quiz_thread.start()
        else:
            logger.info(f"Authentication failed for {addr}")

def main():
    """Main entry point"""
    server = QuizServer()
    server.start_server()

if __name__ == "__main__":
    main()