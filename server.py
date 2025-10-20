import socket
import threading
import json
import time
import traceback
import logging
import os
import queue
import random

HOST = '0.0.0.0'
PORT = 8080
QUESTION_TIME = 15
ACK_TIMEOUT = 2
ACK_RETRIES = 4

clients = {}           # username -> {'addr': addr, 'queue': Queue, 'last_seen': ts}
addr_to_user = {}      # addr -> username
scores = {}
lock = threading.Lock()
msg_queues = {}        # addr -> Queue()

# Setup logging
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    filename=os.path.join(LOG_DIR, "server.log"),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

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

def send_json(sock, data, addr):
    """Send a JSON message over UDP."""
    try:
        payload = json.dumps(data).encode()
        sock.sendto(payload, addr)
    except Exception as e:
        logging.exception("Failed to send to %s: %s", addr, e)

def recv_loop(sock):
    """Receive UDP packets and dispatch to per-client queues."""
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            try:
                msg = json.loads(data.decode())
            except Exception:
                logging.exception("Malformed JSON from %s", addr)
                continue

            # update or create queue for addr
            q = msg_queues.get(addr)
            if not q:
                q = queue.Queue()
                msg_queues[addr] = q

            msg['_addr'] = addr
            q.put(msg)
            # update last seen if known
            with lock:
                user = addr_to_user.get(addr)
                if user and user in clients:
                    clients[user]['last_seen'] = time.time()

        except Exception as e:
            logging.exception("Error in recv_loop: %s", e)
            time.sleep(0.1)

def send_with_ack(sock, msg, addr, expected_ack_type, seq, timeout=ACK_TIMEOUT, retries=ACK_RETRIES):
    """Send msg and wait for an ACK of expected type and matching seq from addr."""
    last_err = None
    for attempt in range(retries):
        try:
            send_json(sock, msg, addr)
            # wait for ack in the addr's queue
            q = msg_queues.get(addr)
            if not q:
                q = queue.Queue()
                msg_queues[addr] = q
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
                    # small best-effort: ignore or stash if needed
                    continue
        except Exception as e:
            last_err = e
            logging.exception("send_with_ack exception to %s: %s", addr, e)
        time.sleep(0.5 * (attempt + 1))
    logging.warning("No ACK received from %s for seq %s after %d tries. Last error: %s", addr, seq, retries, last_err)
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
        with lock:
            clients[username] = {
                'addr': addr,
                'queue': msg_queues.get(addr, queue.Queue()),
                'last_seen': time.time()
            }
            addr_to_user[addr] = username
            msg_queues[addr] = clients[username]['queue']

        ack = {'type': 'auth_ack', 'status': 'ok', 'seq': seq}
        send_with_ack(sock, ack, addr, expected_ack_type='ack', seq=seq)

        logging.info("User %s authenticated from %s", username, addr)
        # start quiz session thread
        threading.Thread(target=quiz_session, args=(sock, username), daemon=True).start()
    else:
        ack = {'type': 'auth_ack', 'status': 'fail', 'seq': seq}
        send_with_ack(sock, ack, addr, expected_ack_type='ack', seq=seq)
        logging.info("Failed auth for %s from %s", username, addr)

def quiz_session(sock, username):
    """Per-client quiz flow: send questions, wait for answers via client's queue."""
    try:
        with lock:
            client_info = clients.get(username)
        if not client_info:
            logging.warning("quiz_session started but client not found: %s", username)
            return
        addr = client_info['addr']
        q = client_info['queue']

        # load questions
        try:
            with open('questions.json', 'r') as f:
                questions = json.load(f)
        except Exception as e:
            logging.exception("Failed to load questions.json: %s", e)
            return

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
            ok = send_with_ack(sock, msg, addr, expected_ack_type='ack', seq=seq)
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
                    send_json(sock, ack, addr)
                    break
                else:
                    # ignore unrelated messages here
                    continue

            correct = (answer == question.get('answer'))
            if correct:
                score += 1
                res_msg = {'type': 'result', 'seq': seq, 'status': 'correct'}
            else:
                res_msg = {'type': 'result', 'seq': seq, 'status': 'wrong', 'correct': question.get('answer')}
            send_json(sock, res_msg, addr)

        # save score and broadcast leaderboard
        with lock:
            scores[username] = score
            leaderboard = sorted(scores.items(), key=lambda x: x[1], reverse=True)
            targets = [info['addr'] for info in clients.values()]

        lb_msg = {'type': 'leaderboard', 'leaderboard': leaderboard}
        for a in targets:
            try:
                send_json(sock, lb_msg, a)
            except Exception:
                logging.exception("Failed to send leaderboard to %s", a)

        logging.info("User %s finished quiz with score %s", username, score)

    except Exception as e:
        logging.exception("Error in quiz_session for %s: %s", username, e)
    finally:
        # clean up client state but keep scores
        with lock:
            info = clients.pop(username, None)
            if info:
                addr_to_user.pop(info['addr'], None)
                msg_queues.pop(info['addr'], None)
        logging.info("Cleaned up session for %s", username)

def start_server():
    """Start the UDP quiz server."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((HOST, PORT))
        logging.info("Server started on %s:%s", HOST, PORT)
        print(f"✅ Server started on {HOST}:{PORT}")
    except Exception as e:
        logging.exception("Failed to start server: %s", e)
        return

    # start receiver thread
    threading.Thread(target=recv_loop, args=(sock,), daemon=True).start()

    # main dispatch loop: listen to new messages in global queues and handle auths
    while True:
        try:
            # scan all queues for auth messages (non-blocking approach)
            for addr, q in list(msg_queues.items()):
                try:
                    while True:
                        msg = q.get_nowait()
                        msg['_addr'] = addr
                        mtype = msg.get('type')
                        if mtype == 'auth':
                            handle_auth_message(sock, msg)
                        else:
                            # Other messages go to per-client queue if bound
                            user = addr_to_user.get(addr)
                            if user and user in clients:
                                # already in client's queue; put back
                                clients[user]['queue'].put(msg)
                            else:
                                # keep it in the addr queue for when client authenticates
                                q.put(msg)
                                break
                except queue.Empty:
                    continue
            time.sleep(0.1)
        except KeyboardInterrupt:
            print("\n🛑 Server shutting down...")
            break
        except Exception as e:
            logging.exception("Unexpected server error in main loop: %s", e)
            time.sleep(1)

    sock.close()

if __name__ == "__main__":
    start_server()
