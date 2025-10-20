import socket
import threading
import sys
import json
import time
import queue
import random
import logging
import os
from exceptions import QuizError, NetworkError, DataFormatError, AuthError

HOST = '127.0.0.1'  # Replace with your server IP
PORT = 8080
ACK_TIMEOUT = 2
ACK_RETRIES = 4
RECONNECT_BACKOFF = [1, 2, 5, 10]

# logging
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    filename=os.path.join(LOG_DIR, "client.log"),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# Clear client log on startup
try:
    open(os.path.join(LOG_DIR, "client.log"), 'w').close()
except Exception:
    pass

recv_queue = queue.Queue()
stop_event = threading.Event()


def send_json(sock, data, addr):
    try:
        try:
            payload = json.dumps(data).encode()
        except (TypeError, ValueError, json.JSONDecodeError) as e:
            raise DataFormatError(f"Failed to serialize message: {e}") from e
        try:
            sock.sendto(payload, addr)
        except OSError as e:
            raise NetworkError(f"Failed to send to {addr}: {e}") from e
    except QuizError as e:
        logging.exception("Send error: %s", e)


def listener(sock):
    """Listen for server messages and enqueue them."""
    while not stop_event.is_set():
        try:
            try:
                data, _ = sock.recvfrom(4096)
            except OSError as e:
                # On Windows UDP, 10054 can indicate server port unreachable (server stopped)
                if getattr(e, 'errno', None) == 10054:
                    raise NetworkError("Server appears to be offline or stopped (ICMP port unreachable).") from e
                raise NetworkError(f"recvfrom failed: {e}") from e
            try:
                msg = json.loads(data.decode())
            except (UnicodeDecodeError, json.JSONDecodeError) as e:
                logging.exception("Malformed JSON from server: %s", e)
                continue
            recv_queue.put(msg)
        except QuizError as e:
            logging.exception("Listener quiz error: %s", e)
        except Exception as e:
            logging.exception("Listener error: %s", e)
            time.sleep(0.5)


def send_with_ack(sock, addr, msg, expected_ack_type, seq, timeout=ACK_TIMEOUT, retries=ACK_RETRIES):
    """Send message and wait for a matching ACK on recv_queue."""
    last_err = None
    for attempt in range(retries):
        try:
            send_json(sock, msg, addr)
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    incoming = recv_queue.get(timeout=deadline - time.time())
                except queue.Empty:
                    break
                if incoming.get('type') == expected_ack_type and incoming.get('seq') == seq:
                    return True
                else:
                    # not the ack we want; keep for the main loop
                    # stash it by putting back
                    recv_queue.put(incoming)
                    break
        except Exception as e:
            last_err = e
            logging.exception("send_with_ack exception: %s", e)
        time.sleep(0.5 * (attempt + 1))
    logging.warning("No ACK received for seq %s after %d tries. Last error: %s", seq, retries, last_err)
    return False


def process_messages(sock):
    """Main processor for messages from server (questions, results, leaderboard)."""
    while not stop_event.is_set():
        try:
            msg = recv_queue.get(timeout=1)
        except queue.Empty:
            continue
        mtype = msg.get('type')
        if mtype == 'question':
            seq = msg.get('seq')
            print("\nQuestion:", msg.get('question'))
            for opt in msg.get('options', []):
                print(opt)
            print(f"You have {msg.get('time')} seconds. Enter A/B/C/D (or press Enter to skip):")

            # Send ACK for question receipt
            ack = {'type': 'ack', 'seq': seq}
            send_json(sock, ack, (HOST, PORT))

            # read answer in another thread to avoid blocking other messages
            answer_holder = {'answer': None}

            def read_input():
                try:
                    ans = input().strip().upper()
                    answer_holder['answer'] = ans if ans else None
                except Exception:
                    answer_holder['answer'] = None

            t = threading.Thread(target=read_input, daemon=True)
            t.start()
            t.join(timeout=msg.get('time', 15))
            ans = answer_holder['answer']
            answer_msg = {'type': 'answer', 'seq': seq, 'answer': ans}
            send_json(sock, answer_msg, (HOST, PORT))

        elif mtype == 'result':
            if msg.get('status') == 'correct':
                print("✅ Correct!")
            else:
                print(f"❌ Wrong. Correct answer: {msg.get('correct')}")
        elif mtype == 'leaderboard':
            print("\n🏆 Leaderboard:")
            for u, s in msg.get('leaderboard', []):
                print(f"{u}: {s}")
        elif mtype == 'auth_ack':
            # handled by send_with_ack flow normally
            recv_queue.put(msg)
        elif mtype == 'ack':
            # put back so waiting send_with_ack can detect it
            recv_queue.put(msg)
        else:
            logging.info("Unhandled message type: %s", mtype)


def authenticate_and_run(username, password):
    """Authenticate to server with retries and run listener + processor."""
    backoff_idx = 0
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            addr = (HOST, PORT)

            # start listener thread
            threading.Thread(target=listener, args=(sock,), daemon=True).start()

            seq = random.randint(1, 1_000_000)
            auth_msg = {'type': 'auth', 'username': username, 'password': password, 'seq': seq}
            ok = send_with_ack(sock, addr, auth_msg, expected_ack_type='auth_ack', seq=seq)
            if not ok:
                raise ConnectionError("Auth ACK not received")

            # server should have replied; but we still wait for final auth_ack content
            # check the auth_ack status
            auth_response = None
            deadline = time.time() + 3
            while time.time() < deadline:
                try:
                    incoming = recv_queue.get(timeout=deadline - time.time())
                except queue.Empty:
                    break
                if incoming.get('type') == 'auth_ack' and incoming.get('seq') == seq:
                    auth_response = incoming
                    break
                else:
                    recv_queue.put(incoming)
                    break

            if not auth_response:
                raise AuthError("No authentication response from server.")
            if auth_response.get('status') != 'ok':
                raise AuthError("Authentication failed.")

            print(f"✅ Authenticated as {username}. Waiting for quiz...")
            # start message processor
            processor_thread = threading.Thread(target=process_messages, args=(sock,), daemon=True)
            processor_thread.start()

            # keep alive loop
            while True:
                time.sleep(1)
                # simple heartbeat: if socket or listener thread died, break and reconnect
                if stop_event.is_set():
                    break

        except AuthError as e:
            logging.exception("Authentication error: %s", e)
            print("⚠️ Authentication error:", e)
            # Give the user another chance to login with new credentials immediately
            try:
                while True:
                    recv_queue.get_nowait()
            except queue.Empty:
                pass
            backoff_idx = 0
            print("Please try logging in again.")
            username = input("Username: ").strip()
            password = input("Password: ").strip()
            continue
        except QuizError as e:
            logging.exception("Quiz error: %s", e)
            print("⚠️ Quiz error:", e)
            backoff = RECONNECT_BACKOFF[min(backoff_idx, len(RECONNECT_BACKOFF)-1)]
            backoff_idx += 1
            print(f"Reconnecting in {backoff} seconds...")
            time.sleep(backoff)
            try:
                while True:
                    recv_queue.get_nowait()
            except queue.Empty:
                pass
            continue
        except Exception as e:
            logging.exception("Connection/auth error: %s", e)
            print("⚠️ Connection/auth error:", e)
            backoff = RECONNECT_BACKOFF[min(backoff_idx, len(RECONNECT_BACKOFF)-1)]
            backoff_idx += 1
            print(f"Reconnecting in {backoff} seconds...")
            time.sleep(backoff)
            try:
                while True:
                    recv_queue.get_nowait()
            except queue.Empty:
                pass
            continue
            backoff = RECONNECT_BACKOFF[min(backoff_idx, len(RECONNECT_BACKOFF)-1)]
            backoff_idx += 1
            print(f"Reconnecting in {backoff} seconds...")
            time.sleep(backoff)
            # clear recv_queue to avoid stale messages
            try:
                while True:
                    recv_queue.get_nowait()
            except queue.Empty:
                pass
            continue
        finally:
            try:
                sock.close()
            except:
                pass


def main():
    """Main client logic."""
    username = input("Username: ").strip()
    password = input("Password: ").strip()
    try:
        authenticate_and_run(username, password)
    except KeyboardInterrupt:
        print("\n🛑 Client exiting...")
    finally:
        stop_event.set()
        print("🔌 Connection closed.")


if __name__ == "__main__":
    main()
