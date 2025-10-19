import socket
import threading
import time
import sys
import logging
from typing import Optional

# -------------------------------
# Client Configuration & Logging
# -------------------------------
HOST = '192.168.1.18'  # Replace with your server IP
PORT = 8080
BUFFER_SIZE = 4096
RECONNECT_DELAY = 5
MAX_RECONNECT_ATTEMPTS = 3
ACK_TIMEOUT = 5

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('client.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class QuizClient:
    def __init__(self):
        self.sock = None
        self.server_addr = (HOST, PORT)
        self.connected = False
        self.username = None
        self.receive_thread = None
        self.running = False
        self.retry_count = 0

    def create_socket(self) -> bool:
        """Create and configure UDP socket"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.settimeout(5.0)  # Initial timeout for connection
            return True
        except socket.error as e:
            logger.error(f"Failed to create socket: {e}")
            return False

    def send_with_retry(self, message: str, max_retries: int = 3) -> bool:
        """Send message with retry mechanism"""
        for attempt in range(max_retries):
            try:
                self.sock.sendto(message.encode(), self.server_addr)
                
                # Send ACK for critical server messages
                if message.startswith(("AUTH_", "ANSWER_")):
                    return self.wait_for_ack(message)
                return True
                
            except socket.error as e:
                logger.warning(f"Send attempt {attempt + 1} failed: {e}")
                if attempt == max_retries - 1:
                    logger.error(f"Failed to send message after {max_retries} attempts")
                    return False
                time.sleep(1)
        return False

    def wait_for_ack(self, original_message: str, timeout: int = ACK_TIMEOUT) -> bool:
        """Wait for ACK from server"""
        original_timeout = self.sock.gettimeout()
        expected_ack = f"ACK_{hash(original_message)}"
        
        try:
            self.sock.settimeout(timeout)
            while True:
                data, addr = self.sock.recvfrom(BUFFER_SIZE)
                if addr == self.server_addr:
                    message = data.decode().strip()
                    if message == expected_ack:
                        return True
        except socket.timeout:
            logger.warning(f"ACK timeout for message: {original_message}")
        except Exception as e:
            logger.warning(f"Error waiting for ACK: {e}")
        finally:
            self.sock.settimeout(original_timeout)
        return False

    def connect_to_server(self) -> bool:
        """Establish connection with server"""
        if not self.create_socket():
            return False

        logger.info(f"Attempting to connect to server at {HOST}:{PORT}")
        
        for attempt in range(MAX_RECONNECT_ATTEMPTS):
            try:
                # Send hello message
                if not self.send_with_retry("hello"):
                    continue

                # Wait for authentication request
                self.sock.settimeout(10)
                data, addr = self.sock.recvfrom(BUFFER_SIZE)
                
                if addr == self.server_addr and data.decode().startswith("AUTH_REQ"):
                    self.connected = True
                    self.sock.settimeout(None)  # Reset to blocking
                    logger.info("✅ Successfully connected to server")
                    return True
                    
            except socket.timeout:
                logger.warning(f"Connection attempt {attempt + 1} timed out")
            except Exception as e:
                logger.error(f"Connection attempt {attempt + 1} failed: {e}")
            
            if attempt < MAX_RECONNECT_ATTEMPTS - 1:
                logger.info(f"Retrying connection in {RECONNECT_DELAY} seconds...")
                time.sleep(RECONNECT_DELAY)
        
        logger.error("Failed to connect to server after all attempts")
        return False

    def authenticate(self) -> bool:
        """Handle authentication with server"""
        try:
            # Send username
            self.username = input("Enter your username: ").strip()
            if not self.send_with_retry(self.username):
                return False

            # Wait for username ACK
            self.sock.settimeout(10)
            data, addr = self.sock.recvfrom(BUFFER_SIZE)
            if addr != self.server_addr or not data.decode().startswith("ACK_USERNAME"):
                logger.error("Username acknowledgement failed")
                return False

            # Send password
            password = input("Enter your password: ").strip()
            if not self.send_with_retry(password):
                return False

            # Wait for authentication result
            data, addr = self.sock.recvfrom(BUFFER_SIZE)
            if addr != self.server_addr:
                return False

            auth_result = data.decode()
            if auth_result.startswith("AUTH_SUCCESS"):
                logger.info(f"✅ Authentication successful! Welcome {self.username}!")
                return True
            else:
                logger.error("❌ Authentication failed. Please check your credentials.")
                return False

        except socket.timeout:
            logger.error("Authentication timeout")
            return False
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False
        finally:
            self.sock.settimeout(None)

    def receive_messages(self):
        """Continuously listen for messages from server"""
        while self.running and self.connected:
            try:
                data, addr = self.sock.recvfrom(BUFFER_SIZE)
                if addr == self.server_addr:
                    message = data.decode()
                    
                    # Handle ACK requests
                    if message.startswith("ACK_"):
                        self.sock.sendto(message.encode(), self.server_addr)
                    # Handle questions
                    elif message.startswith("QUESTION_"):
                        # Extract and display question
                        question_parts = message.split('_', 2)
                        if len(question_parts) >= 3:
                            print(f"\n{question_parts[2]}")
                    else:
                        print(f"\n{message}")
                        
            except socket.timeout:
                continue  # Expected with timeout set
            except ConnectionResetError:
                logger.error("❌ Connection reset by server")
                self.connected = False
                break
            except OSError as e:
                if self.running:  # Only log if we're supposed to be running
                    logger.error(f"❌ Network error: {e}")
                    self.connected = False
                break
            except Exception as e:
                if self.running:
                    logger.error(f"❌ Error receiving message: {e}")
                    self.connected = False
                break

    def send_answers(self):
        """Handle user input for quiz answers"""
        while self.running and self.connected:
            try:
                answer = input().strip().upper()
                
                if not self.connected:
                    break
                    
                if answer == 'EXIT':
                    logger.info("Disconnecting by user request...")
                    self.running = False
                    break
                
                if answer in ['A', 'B', 'C', 'D']:
                    if not self.send_with_retry(f"ANSWER_{answer}"):
                        logger.error("Failed to send answer")
                else:
                    print("Please enter A, B, C, or D")
                    
            except EOFError:
                break  # Handle Ctrl+D gracefully
            except Exception as e:
                logger.error(f"Error processing input: {e}")
                if self.connected:
                    self.connected = False

    def handle_reconnection(self):
        """Attempt to reconnect to server"""
        if self.retry_count >= MAX_RECONNECT_ATTEMPTS:
            logger.error("Max reconnection attempts reached. Giving up.")
            return False

        self.retry_count += 1
        logger.info(f"Attempting to reconnect ({self.retry_count}/{MAX_RECONNECT_ATTEMPTS})...")
        
        time.sleep(RECONNECT_DELAY)
        if self.connect_to_server() and self.authenticate():
            self.retry_count = 0
            return True
        return False

    def start_client(self):
        """Main client loop"""
        logger.info("🚀 Starting UDP Quiz Client...")
        
        if not self.connect_to_server():
            logger.error("Failed to establish initial connection")
            return

        if not self.authenticate():
            logger.error("Authentication failed")
            return

        # Start receiving thread
        self.running = True
        self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
        self.receive_thread.start()

        logger.info("💡 Quiz started! Type your answers (A/B/C/D) or 'exit' to quit.")

        try:
            self.send_answers()
        except KeyboardInterrupt:
            logger.info("\n🛑 Client interrupted by user")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
        finally:
            self.cleanup()

    def cleanup(self):
        """Clean up resources"""
        self.running = False
        self.connected = False
        
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
        
        logger.info("🔌 Client shutdown complete")

def main():
    """Main entry point"""
    client = QuizClient()
    
    try:
        client.start_client()
    except Exception as e:
        logger.critical(f"Client crashed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()