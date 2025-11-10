🧠 Live Quiz Server (HTTP/HTTPS Version)

A real-time multiplayer quiz game built using Python’s FastAPI framework with HTTP/HTTPS support. Players can join from multiple devices, answer quiz questions, and see a live leaderboard update in real-time. The server can be deployed behind Apache with SSL/TLS support.

🎯 Features

🧩 Multiplayer support: Multiple clients can connect simultaneously

🕒 Timed questions: Each player has a time limit per question

🧑‍💻 Authentication: Username/password required before joining

🧾 Dynamic leaderboard: Updated after each player finishes

🧠 JSON-based questions: Easily customizable

🌐 HTTP/HTTPS support: Works with Apache reverse proxy and SSL/TLS

🔒 Secure connections: SSL/TLS encryption support

📡 REST API: Standard HTTP endpoints for easy integration

🏗️ Tech Stack

Language: Python 3.8+

Libraries: FastAPI, uvicorn, requests

Protocol: HTTP/HTTPS with REST API

Files:

server.py → The quiz server (FastAPI application)

client.py → The quiz client (Command-line HTTP client)

client_gui.py → The quiz client (GUI version with tkinter)

questions.json → Stores quiz questions

users.json → Stores usernames and passwords

apache_ssl.conf → Apache configuration for SSL/TLS reverse proxy

📁 Project Structure
📦 live-quiz-server
 ┣ 📜 server.py
 ┣ 📜 client.py
 ┣ 📜 questions.json
 ┣ 📜 users.json
 ┣ 📜 apache_ssl.conf
 ┣ 📜 requirements.txt
 ┣ 📜 APACHE_SETUP.md
 ┗ 📜 README.md

⚙️ How It Works

The server runs as a FastAPI HTTP/HTTPS application listening on a specific IP and port.

Each client connects via HTTP requests, authenticates with username/password, and receives a session ID.

The server provides REST API endpoints for quiz operations:
- Authentication endpoint
- Start quiz endpoint
- Get question endpoint
- Submit answer endpoint
- Leaderboard endpoint

Clients poll the server for questions and submit answers via HTTP POST requests.

At the end, all players can see the final leaderboard.

🚀 Setup Guide

1️⃣ Install Python

Make sure Python 3.8 or higher is installed.

Check using:

python --version

2️⃣ Install Dependencies

Install required Python packages:

pip install -r requirements.txt

This will install:
- FastAPI (web framework)
- uvicorn (ASGI server)
- requests (HTTP client library)
- cryptography (for SSL certificate generation, optional)

3️⃣ Prepare Files

Ensure all project files are in the same directory:
- server.py
- client.py
- questions.json
- users.json
- exceptions.py

4️⃣ Configure Server

The server runs on `http://127.0.0.1:8080` by default. You can modify these settings in `server.py`:

```python
HOST = '127.0.0.1'  # Change to '0.0.0.0' to allow external connections
PORT = 8080
USE_SSL = True  # Enable HTTPS/SSL support
```

5️⃣ Start the Server

Run:

python server.py

Output:

✅ HTTP server started on https://127.0.0.1:8080
   🔒 HTTPS/SSL enabled
   Configure Apache to proxy HTTP requests to this server

6️⃣ Run the Client

You have two options for the client:

**Option A: GUI Client (Recommended)**

Run the graphical user interface:

```bash
python client_gui.py
```

The GUI client provides:
- Modern, user-friendly interface
- Visual question display with clickable options
- Real-time timer and score display
- Live leaderboard updates
- Server URL configuration

**Option B: Command Line Client**

Open `client.py` and update if needed:

```python
HOST = '127.0.0.1'  # or your server's IP address
PORT = 8080  # or 443 if using Apache
BASE_URL = f'https://{HOST}:{PORT}'  # or http:// if not using SSL
```

Then run:

```bash
python client.py
```

7️⃣ Play!

Each player enters a username and password.

The quiz begins, one question at a time.

After the quiz, everyone sees the shared leaderboard.

🌐 Apache Setup (Optional)

For production deployment with SSL/TLS termination:

1. Install and configure Apache 2.4+
2. Enable required modules (mod_ssl, mod_proxy, mod_proxy_http)
3. Copy `apache_ssl.conf` to your Apache configuration
4. Update certificate paths and ServerName in the config
5. Restart Apache

See `APACHE_SETUP.md` for detailed instructions.

📋 JSON Files

🧾 questions.json

Example:

```json
[
  {
    "question": "What is the capital of France?",
    "options": ["A) Berlin", "B) Paris", "C) Rome", "D) Madrid"],
    "answer": "B"
  }
]
```

🔐 users.json

Example:

```json
{
  "fady": "fady123",
  "fares": "pass123",
  "youssef": "54321"
}
```

📡 API Endpoints

- `POST /api/auth` - Authenticate user (returns session ID)
- `GET /api/quiz/start` - Start quiz session (requires X-Session-ID header)
- `GET /api/quiz/question` - Get current question (requires X-Session-ID header)
- `POST /api/quiz/answer` - Submit answer (requires X-Session-ID header)
- `GET /api/quiz/leaderboard` - Get current leaderboard
- `GET /api/quiz/stream` - Server-Sent Events stream for real-time updates
- `GET /api/health` - Health check endpoint

🌐 Connecting from Other Devices

✅ All devices must be on the same network (or use public IP/domain)

✅ Use the server's IP address (not 127.0.0.1 for remote connections)

✅ If using Apache, connect via HTTPS on port 443

✅ If Windows Firewall blocks connections:
   - Go to Windows Defender Firewall → Allow an app → Allow Python
   - Or allow port 8080 (or 443 if using Apache) for private networks

🛠️ Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| ❌ Connection refused | Wrong IP or port | Use the correct IP and port |
| 🔥 Timeout / no response | Firewall blocking port | Allow Python or open TCP 8080/443 |
| ❓ Can't connect | Not same network | Connect all devices to same network |
| ⚙️ SSL certificate error | Self-signed certificate | Accept certificate warning or use valid cert |
| 🔒 401 Unauthorized | Invalid session | Re-authenticate with username/password |
| 📡 502 Bad Gateway | Backend not running | Ensure Python server is running on port 8080 |

💡 Ideas for Extension

🪄 Web-based GUI using React or Vue.js

🌍 Remote access using port forwarding or cloud deployment

📊 Real-time leaderboard updates using WebSockets or SSE

🔒 Password hashing for users (with bcrypt)

🎮 Room-based multiplayer (Room A, Room B, etc.)

📱 Mobile app integration via REST API

👨‍💻 Example Output

```
==================================================
Quiz Client - HTTP/HTTPS Version
==================================================
Username: fady
Password: fady123
✅ Authenticated as fady. Starting quiz...
✅ Quiz started! 10 questions, 15 seconds per question

Question 1/10: What is the capital of France?
A) Berlin
B) Paris
C) Rome
D) Madrid
You have 15 seconds. Enter A/B/C/D (or press Enter to skip):
> B
✅ Correct!
Current score: 1/1

...

🏆 Leaderboard:
fady: 8
fares: 6
youssef: 5

✅ Quiz completed! Your final score: 8/10
```

🏁 License

This project is open-source and free for educational use.
