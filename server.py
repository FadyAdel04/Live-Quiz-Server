import socket
import threading
import json
import time
import traceback
import logging
import os
import queue
import random
import ssl
from exceptions import QuizError, NetworkError, DataFormatError, ResourceLoadError, AuthError

HOST = '127.0.0.1'
PORT = 8080
USE_SSL = True
SSL_CERT_FILE = 'ssl/server.crt'
SSL_KEY_FILE = 'ssl/server.key'
QUESTION_TIME = 15
ACK_TIMEOUT = 2
ACK_RETRIES = 4

clients = {}           # username -> {'sock': sock, 'queue': Queue, 'last_seen': ts, 'addr': addr}
sock_to_user = {}      # sock -> username
scores = {}
lock = threading.Lock()
client_sockets = {}    # username -> sock

# Setup logging
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    filename=os.path.join(LOG_DIR, "server.log"),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# Clear server log on startup
try:
    open(os.path.join(LOG_DIR, "server.log"), 'w').close()
except Exception:
    pass

def load_users():
    """Load registered users from users.json"""
    try:
        with open('users.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logging.warning("users.json not found; continuing with empty users.")
        return {}
    except json.JSONDecodeError:
        logging.error("users.json not valid JSON; continuing with empty users.")
        return {}

def send_json(sock, data):
    """Send a JSON message over TCP."""
    try:
        payload = json.dumps(data).encode() + b'\n'
        sock.sendall(payload)
    except (OSError, TimeoutError, BrokenPipeError, ConnectionResetError) as e:
        raise NetworkError(f"Failed to send: {e}") from e
    except (TypeError, ValueError, json.JSONDecodeError) as e:
        raise DataFormatError(f"Failed to serialize message: {e}") from e

def handle_client(client_sock, addr):
    """Handle a single client connection."""
    try:
        buffer = b''
        while True:
            try:
                data = client_sock.recv(4096)
                if not data:
                    break
                buffer += data
                while b'\n' in buffer:
                    line, buffer = buffer.split(b'\n', 1)
                    if not line:
                        continue
                    try:
                        msg = json.loads(line.decode())
                    except (UnicodeDecodeError, json.JSONDecodeError) as e:
                        logging.exception("Malformed JSON from %s", addr)
                        continue
                    
                    msg['_addr'] = addr
                    msg['_sock'] = client_sock
                    
                    # Route message based on type
                    mtype = msg.get('type')
                    if mtype == 'auth':
                        handle_auth_message(client_sock, msg)
                    else:
                        # Route to client's queue if authenticated
                        with lock:
                            user = sock_to_user.get(client_sock)
                            if user and user in clients:
                                clients[user]['queue'].put(msg)
                                clients[user]['last_seen'] = time.time()
                            else:
                                # Not authenticated, discard
                                logging.warning("Message from unauthenticated client %s", addr)
            except (OSError, ConnectionResetError, BrokenPipeError) as e:
                logging.info("Client %s disconnected: %s", addr, e)
                break
            except Exception as e:
                logging.exception("Error handling client %s: %s", addr, e)
                break
    except Exception as e:
        logging.exception("Error in handle_client for %s: %s", addr, e)
    finally:
        # Cleanup client
        with lock:
            user = sock_to_user.pop(client_sock, None)
            if user:
                clients.pop(user, None)
                client_sockets.pop(user, None)
                logging.info("Cleaned up client %s (user: %s)", addr, user)
        try:
            client_sock.close()
        except:
            pass

def send_with_ack(sock, msg, q, expected_ack_type, seq, timeout=ACK_TIMEOUT, retries=ACK_RETRIES):
    """Send msg and wait for an ACK of expected type and matching seq."""
    last_err = None
    for attempt in range(retries):
        try:
            send_json(sock, msg)
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    incoming = q.get(timeout=deadline - time.time())
                except queue.Empty:
                    break
                if incoming.get('type') == expected_ack_type and incoming.get('seq') == seq:
                    return True
                else:
                    # not the ack we expected; push back for other handlers
                    q.put(incoming)
                    break
        except Exception as e:
            last_err = e
            logging.exception("send_with_ack exception: %s", e)
        time.sleep(0.5 * (attempt + 1))
    logging.warning("No ACK received for seq %s after %d tries. Last error: %s", seq, retries, last_err)
    return False

def handle_auth_message(sock, msg):
    """Handle incoming auth message, reply with auth_ack and start session."""
    addr = msg.get('_addr')
    username = msg.get('username')
    password = msg.get('password')
    seq = msg.get('seq', random.randint(1, 1_000_000))
    users = load_users()

    if username in users and users[username] == password:
        # create client entry
        client_queue = queue.Queue()
        with lock:
            clients[username] = {
                'sock': sock,
                'addr': addr,
                'queue': client_queue,
                'last_seen': time.time()
            }
            sock_to_user[sock] = username
            client_sockets[username] = sock

        ack = {'type': 'auth_ack', 'status': 'ok', 'seq': seq}
        try:
            send_json(sock, ack)
            # Ensure SSL socket flushes if it's an SSL socket
            if hasattr(sock, 'flush'):
                try:
                    sock.flush()
                except:
                    pass
            logging.debug("Sent auth_ack to %s for user %s", addr, username)
        except QuizError as e:
            logging.exception("Failed to send auth_ack: %s", e)
            return

        logging.info("User %s authenticated from %s", username, addr)
        # start quiz session thread
        threading.Thread(target=quiz_session, args=(sock, username), daemon=True).start()
    else:
        ack = {'type': 'auth_ack', 'status': 'fail', 'seq': seq}
        try:
            send_json(sock, ack)
            # Ensure SSL socket flushes if it's an SSL socket
            if hasattr(sock, 'flush'):
                try:
                    sock.flush()
                except:
                    pass
            logging.debug("Sent auth_ack (fail) to %s for user %s", addr, username)
        except QuizError as e:
            logging.exception("Failed to send auth_ack: %s", e)
        logging.info("Failed auth for %s from %s", username, addr)

def quiz_session(sock, username):
    """Per-client quiz flow: send questions, wait for answers via client's queue."""
    try:
        with lock:
            client_info = clients.get(username)
        if not client_info:
            logging.warning("quiz_session started but client not found: %s", username)
            return
        q = client_info['queue']

        # load questions
        try:
            with open('questions.json', 'r') as f:
                questions = json.load(f)
        except FileNotFoundError as e:
            raise ResourceLoadError(f"questions.json not found: {e}") from e
        except json.JSONDecodeError as e:
            raise DataFormatError(f"questions.json is invalid JSON: {e}") from e
        except Exception as e:
            raise ResourceLoadError(f"Failed to load questions.json: {e}") from e

        score = 0
        for idx, question in enumerate(questions, start=1):
            seq = random.randint(1, 1_000_000)
            msg = {
                'type': 'question',
                'seq': seq,
                'index': idx,
                'question': question['question'],
                'options': question['options'],
                'time': QUESTION_TIME
            }
            ok = send_with_ack(sock, msg, q, expected_ack_type='ack', seq=seq)
            if not ok:
                logging.warning("Client %s did not ACK question %s; continuing.", username, seq)

            # wait for answer or timeout
            answer = None
            deadline = time.time() + QUESTION_TIME
            while time.time() < deadline:
                try:
                    incoming = q.get(timeout=deadline - time.time())
                except queue.Empty:
                    break
                if incoming.get('type') == 'answer' and incoming.get('seq') == seq:
                    answer = incoming.get('answer')
                    # send answer ACK to client
                    ack = {'type': 'ack', 'seq': seq}
                    try:
                        send_json(sock, ack)
                    except QuizError as e:
                        logging.exception("Failed to send ACK: %s", e)
                    break
                else:
                    # ignore unrelated messages here
                    q.put(incoming)
                    break

            correct = (answer == question.get('answer'))
            if correct:
                score += 1
                res_msg = {'type': 'result', 'seq': seq, 'status': 'correct'}
            else:
                res_msg = {'type': 'result', 'seq': seq, 'status': 'wrong', 'correct': question.get('answer')}
            try:
                send_json(sock, res_msg)
            except QuizError as e:
                logging.exception("Failed to send result: %s", e)

        # save score and broadcast leaderboard
        with lock:
            scores[username] = score
            leaderboard = sorted(scores.items(), key=lambda x: x[1], reverse=True)
            target_socks = [info['sock'] for info in clients.values() if info['sock'] != sock]

        lb_msg = {'type': 'leaderboard', 'leaderboard': leaderboard}
        # Send to current client
        try:
            send_json(sock, lb_msg)
        except QuizError as e:
            logging.exception("Failed to send leaderboard: %s", e)
        
        # Send to other clients
        for target_sock in target_socks:
            try:
                send_json(target_sock, lb_msg)
            except QuizError as e:
                logging.exception("Failed to send leaderboard: %s", e)

        logging.info("User %s finished quiz with score %s", username, score)

    except QuizError as e:
        logging.exception("Quiz error in quiz_session for %s: %s", username, e)
    except Exception as e:
        logging.exception("Error in quiz_session for %s: %s", username, e)

def start_server():
    """Start the TCP quiz server with optional SSL."""
    try:
        # Create SSL context if using SSL
        ssl_context = None
        if USE_SSL:
            try:
                os.makedirs('ssl', exist_ok=True)
                if not os.path.exists(SSL_CERT_FILE) or not os.path.exists(SSL_KEY_FILE):
                    logging.warning("SSL certificate files not found. Generating self-signed certificate...")
                    generate_self_signed_cert()
                
                ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                ssl_context.load_cert_chain(SSL_CERT_FILE, SSL_KEY_FILE)
                logging.info("SSL enabled. Using certificate: %s", SSL_CERT_FILE)
            except Exception as e:
                logging.error("Failed to setup SSL: %s. Continuing without SSL...", e)
                ssl_context = None

        # Create TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((HOST, PORT))
            sock.listen(10)
        except OSError as e:
            raise NetworkError(f"Failed to bind {HOST}:{PORT}: {e}") from e
        
        ssl_status = "with SSL" if ssl_context else "without SSL"
        logging.info("Server started on %s:%s %s", HOST, PORT, ssl_status)
        print(f"✅ Server started on {HOST}:{PORT} {ssl_status}")

        # Accept connections
        while True:
            try:
                client_sock, addr = sock.accept()
                logging.info("New connection from %s", addr)
                
                # Wrap with SSL if enabled
                if ssl_context:
                    try:
                        client_sock = ssl_context.wrap_socket(client_sock, server_side=True)
                        logging.info("SSL handshake completed for %s", addr)
                    except Exception as e:
                        logging.error("SSL handshake failed for %s: %s", addr, e)
                        client_sock.close()
                        continue
                
                # Handle client in separate thread
                threading.Thread(target=handle_client, args=(client_sock, addr), daemon=True).start()
                
            except KeyboardInterrupt:
                print("\n🛑 Server shutting down...")
                break
            except Exception as e:
                logging.exception("Error accepting connection: %s", e)
                time.sleep(1)

    except QuizError as e:
        logging.exception("Failed to start server: %s", e)
    except Exception as e:
        logging.exception("Unexpected server error: %s", e)
    finally:
        try:
            sock.close()
        except:
            pass

def generate_self_signed_cert():
    """Generate a self-signed SSL certificate for development."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime
        import ipaddress
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Quiz Server"),
            x509.NameAttribute(NameOID.COMMON_NAME, HOST),
        ])
        
        # Add Subject Alternative Name (SAN)
        san_list = [x509.DNSName(HOST)]
        try:
            # Try to add IP address if HOST is an IP
            # Verify it's a valid IP by parsing it
            ip_obj = ipaddress.IPv4Address(HOST)
            san_list.append(x509.IPAddress(ip_obj))
        except ValueError:
            # Not an IP address, skip IP address in SAN
            pass
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        # Write certificate
        with open(SSL_CERT_FILE, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        # Write private key
        with open(SSL_KEY_FILE, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        logging.info("Generated self-signed certificate: %s", SSL_CERT_FILE)
        print("📜 Generated self-signed SSL certificate")
    except ImportError:
        logging.warning("cryptography library not found. Please install it or provide SSL certificates manually.")
        print("⚠️ Please install cryptography library: pip install cryptography")
        print("   Or provide SSL certificate files manually in the ssl/ directory")

if __name__ == "__main__":
    start_server()
