import asyncio
import json
import time
import random
import logging
import os
import websockets
from websockets.exceptions import ConnectionClosed, WebSocketException
from exceptions import QuizError, NetworkError, DataFormatError, AuthError

HOST = '127.0.0.1'  # Replace with your server IP or Apache server
PORT = 8080
USE_SSL = False  # Apache handles SSL, use wss:// when connecting through Apache
WS_URL = f'ws://{HOST}:{PORT}'  # Use wss:// when connecting through Apache HTTPS
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

recv_queue = asyncio.Queue()
stop_event = asyncio.Event()


async def send_json(ws, data):
    try:
        try:
            payload = json.dumps(data)
        except (TypeError, ValueError, json.JSONDecodeError) as e:
            raise DataFormatError(f"Failed to serialize message: {e}") from e
        try:
            await ws.send(payload)
        except (ConnectionClosed, WebSocketException) as e:
            raise NetworkError(f"Failed to send: {e}") from e
    except QuizError as e:
        logging.exception("Send error: %s", e)


async def listener(ws):
    """Listen for server messages and enqueue them."""
    try:
        async for message in ws:
            try:
                msg = json.loads(message)
                await recv_queue.put(msg)
            except (UnicodeDecodeError, json.JSONDecodeError) as e:
                logging.exception("Malformed JSON from server: %s", e)
                continue
    except ConnectionClosed:
        logging.info("Server closed connection")
    except Exception as e:
        logging.exception("Listener error: %s", e)
        raise NetworkError(f"recv failed: {e}") from e


async def send_with_ack(ws, msg, expected_ack_type, seq, timeout=ACK_TIMEOUT, retries=ACK_RETRIES):
    """Send message and wait for a matching ACK on recv_queue."""
    last_err = None
    for attempt in range(retries):
        try:
            await send_json(ws, msg)
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    incoming = await asyncio.wait_for(recv_queue.get(), timeout=deadline - time.time())
                except asyncio.TimeoutError:
                    break
                if incoming.get('type') == expected_ack_type and incoming.get('seq') == seq:
                    return True
                else:
                    # not the ack we want; keep for the main loop
                    # stash it by putting back
                    await recv_queue.put(incoming)
                    break
        except Exception as e:
            last_err = e
            logging.exception("send_with_ack exception: %s", e)
        await asyncio.sleep(0.5 * (attempt + 1))
    logging.warning("No ACK received for seq %s after %d tries. Last error: %s", seq, retries, last_err)
    return False


async def process_messages(ws):
    """Main processor for messages from server (questions, results, leaderboard)."""
    while not stop_event.is_set():
        try:
            msg = await asyncio.wait_for(recv_queue.get(), timeout=1.0)
        except asyncio.TimeoutError:
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
            await send_json(ws, ack)

            # read answer with timeout
            answer_holder = {'answer': None}
            loop = asyncio.get_event_loop()
            
            def read_input():
                try:
                    ans = input().strip().upper()
                    answer_holder['answer'] = ans if ans else None
                except Exception:
                    answer_holder['answer'] = None

            # Run input in executor to avoid blocking
            try:
                await asyncio.wait_for(
                    loop.run_in_executor(None, read_input),
                    timeout=msg.get('time', 15)
                )
            except asyncio.TimeoutError:
                pass
            
            ans = answer_holder['answer']
            answer_msg = {'type': 'answer', 'seq': seq, 'answer': ans}
            await send_json(ws, answer_msg)

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
            await recv_queue.put(msg)
        elif mtype == 'ack':
            # put back so waiting send_with_ack can detect it
            await recv_queue.put(msg)
        else:
            logging.info("Unhandled message type: %s", mtype)


async def authenticate_and_run(username, password):
    """Authenticate to server with retries and run listener + processor."""
    backoff_idx = 0
    while True:
        ws = None
        try:
            # Connect to WebSocket server
            try:
                ws = await websockets.connect(WS_URL)
                logging.info("Connected to WebSocket server")
            except Exception as e:
                raise NetworkError(f"Failed to connect to {WS_URL}: {e}") from e

            # start listener task
            listener_task = asyncio.create_task(listener(ws))

            seq = random.randint(1, 1_000_000)
            auth_msg = {'type': 'auth', 'username': username, 'password': password, 'seq': seq}
            
            # Send auth message and wait for auth_ack response
            logging.info("Sending auth message with seq %s", seq)
            await send_json(ws, auth_msg)
            
            # Wait for auth_ack response
            auth_response = None
            deadline = time.time() + 5  # 5 second timeout
            while time.time() < deadline:
                try:
                    timeout = max(0.1, deadline - time.time())
                    incoming = await asyncio.wait_for(recv_queue.get(), timeout=timeout)
                    logging.debug("Received message type: %s, seq: %s (waiting for auth_ack, seq: %s)", 
                                incoming.get('type'), incoming.get('seq'), seq)
                except asyncio.TimeoutError:
                    logging.debug("Timeout waiting for auth_ack, time remaining: %.2f", deadline - time.time())
                    break
                if incoming.get('type') == 'auth_ack' and incoming.get('seq') == seq:
                    auth_response = incoming
                    logging.info("Received auth_ack with status: %s", incoming.get('status'))
                    break
                else:
                    # Put back for other handlers, continue looking
                    await recv_queue.put(incoming)
                    continue
            
            if not auth_response:
                raise AuthError("No authentication response from server.")
            if auth_response.get('status') != 'ok':
                raise AuthError("Authentication failed.")

            print(f"✅ Authenticated as {username}. Waiting for quiz...")
            # start message processor
            processor_task = asyncio.create_task(process_messages(ws))

            # keep alive loop - wait for tasks to complete
            done, pending = await asyncio.wait(
                [listener_task, processor_task],
                return_when=asyncio.FIRST_COMPLETED
            )
            
            # If either task completed, reconnect
            if done:
                logging.info("Connection lost, reconnecting...")
                for task in pending:
                    task.cancel()
                break

        except AuthError as e:
            logging.exception("Authentication error: %s", e)
            print("⚠️ Authentication error:", e)
            # Give the user another chance to login with new credentials immediately
            # Clear queue
            while not recv_queue.empty():
                try:
                    await recv_queue.get()
                except:
                    break
            backoff_idx = 0
            print("Please try logging in again.")
            loop = asyncio.get_event_loop()
            username = await loop.run_in_executor(None, input, "Username: ")
            username = username.strip()
            password = await loop.run_in_executor(None, input, "Password: ")
            password = password.strip()
            continue
        except QuizError as e:
            logging.exception("Quiz error: %s", e)
            print("⚠️ Quiz error:", e)
            backoff = RECONNECT_BACKOFF[min(backoff_idx, len(RECONNECT_BACKOFF)-1)]
            backoff_idx += 1
            print(f"Reconnecting in {backoff} seconds...")
            await asyncio.sleep(backoff)
            # Clear queue
            while not recv_queue.empty():
                try:
                    await recv_queue.get()
                except:
                    break
            continue
        except Exception as e:
            logging.exception("Connection/auth error: %s", e)
            print("⚠️ Connection/auth error:", e)
            backoff = RECONNECT_BACKOFF[min(backoff_idx, len(RECONNECT_BACKOFF)-1)]
            backoff_idx += 1
            print(f"Reconnecting in {backoff} seconds...")
            await asyncio.sleep(backoff)
            # Clear queue
            while not recv_queue.empty():
                try:
                    await recv_queue.get()
                except:
                    break
            continue
        finally:
            if ws:
                try:
                    await ws.close()
                except:
                    pass


async def main():
    """Main client logic."""
    loop = asyncio.get_event_loop()
    username = await loop.run_in_executor(None, input, "Username: ")
    username = username.strip()
    password = await loop.run_in_executor(None, input, "Password: ")
    password = password.strip()
    try:
        await authenticate_and_run(username, password)
    except KeyboardInterrupt:
        print("\n🛑 Client exiting...")
    finally:
        stop_event.set()
        print("🔌 Connection closed.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 Client exiting...")
