import json
import time
import logging
import os
import random
import ssl
import asyncio
from typing import Dict, Optional
from datetime import datetime

from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from exceptions import QuizError, NetworkError, DataFormatError, ResourceLoadError, AuthError

HOST = '127.0.0.1'
PORT = 8080
USE_SSL = True  # Enable HTTPS/SSL support
SSL_CERT_FILE = 'ssl/server.crt'
SSL_KEY_FILE = 'ssl/server.key'
QUESTION_TIME = 15

# In-memory storage
clients: Dict[str, Dict] = {}  # username -> {'session_id': str, 'last_seen': float, 'current_question': int, 'score': int}
sessions: Dict[str, str] = {}  # session_id -> username
scores: Dict[str, int] = {}
active_quizzes: Dict[str, Dict] = {}  # username -> quiz state

app = FastAPI(title="Quiz Server", version="2.0")

# CORS middleware for web clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify allowed origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Custom formatter to replace log levels with HTTP status codes
class StatusCodeFormatter(logging.Formatter):
    """Formatter that replaces log levels with HTTP status codes."""
    STATUS_CODES = {
        logging.DEBUG: 100,
        logging.INFO: 200,
        logging.WARNING: 300,
        logging.ERROR: 500,
        logging.CRITICAL: 500
    }
    
    def format(self, record):
        # Replace levelname with status code
        status_code = self.STATUS_CODES.get(record.levelno, 200)
        record.levelname = str(status_code)
        return super().format(record)

# Setup logging
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

# Create logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Create file handler with custom formatter
file_handler = logging.FileHandler(os.path.join(LOG_DIR, "server.log"))
file_handler.setFormatter(StatusCodeFormatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(file_handler)

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

def load_questions():
    """Load questions from questions.json"""
    try:
        with open('questions.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError as e:
        raise ResourceLoadError(f"questions.json not found: {e}") from e
    except json.JSONDecodeError as e:
        raise DataFormatError(f"questions.json is invalid JSON: {e}") from e
    except Exception as e:
        raise ResourceLoadError(f"Failed to load questions.json: {e}") from e

@app.get("/")
async def root():
    """Root endpoint - API information."""
    return JSONResponse({
        'status': 'ok',
        'message': 'Live Quiz Server API',
        'version': '2.0',
        'endpoints': {
            'docs': '/docs',
            'redoc': '/redoc',
            'health': '/api/health',
            'auth': '/api/auth',
            'quiz_start': '/api/quiz/start',
            'quiz_question': '/api/quiz/question',
            'quiz_answer': '/api/quiz/answer',
            'leaderboard': '/api/quiz/leaderboard',
            'quiz_stream': '/api/quiz/stream'
        }
    })

@app.post("/api/auth")
async def authenticate(request: Request):
    """Authenticate user and return session ID."""
    try:
        data = await request.json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            raise HTTPException(status_code=400, detail="Username and password required")
        
        users = load_users()
        
        if username in users and users[username] == password:
            # Generate session ID
            session_id = f"{username}_{int(time.time())}_{random.randint(1000, 9999)}"
            sessions[session_id] = username
            
            # Initialize client
            clients[username] = {
                'session_id': session_id,
                'last_seen': time.time(),
                'current_question': 0,
                'score': 0,
                'started': False
            }
            
            logging.info("User %s authenticated from %s", username, request.client.host)
            return JSONResponse({
                'status': 'ok',
                'session_id': session_id,
                'username': username
            })
        else:
            logging.info("Failed auth for %s from %s", username, request.client.host)
            raise HTTPException(status_code=401, detail="Authentication failed")
            
    except HTTPException:
        raise
    except Exception as e:
        logging.exception("Auth error: %s", e)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/quiz/start")
async def start_quiz(session_id: str = Header(..., alias="X-Session-ID")):
    """Start quiz session for authenticated user."""
    try:
        username = sessions.get(session_id)
        if not username or username not in clients:
            raise HTTPException(status_code=401, detail="Invalid or expired session")
        
        client = clients[username]
        if client['started']:
            raise HTTPException(status_code=400, detail="Quiz already started")
        
        # Initialize quiz state
        questions = load_questions()
        client['started'] = True
        client['current_question'] = 0
        client['score'] = 0
        client['last_seen'] = time.time()
        
        active_quizzes[username] = {
            'questions': questions,
            'start_time': time.time(),
            'current_index': 0
        }
        
        logging.info("Quiz started for user %s", username)
        return JSONResponse({
            'status': 'ok',
            'total_questions': len(questions),
            'question_time': QUESTION_TIME
        })
        
    except HTTPException:
        raise
    except Exception as e:
        logging.exception("Start quiz error: %s", e)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/quiz/question")
async def get_question(session_id: str = Header(..., alias="X-Session-ID")):
    """Get current question for the user."""
    try:
        username = sessions.get(session_id)
        if not username or username not in clients:
            raise HTTPException(status_code=401, detail="Invalid or expired session")
        
        client = clients[username]
        if not client['started']:
            raise HTTPException(status_code=400, detail="Quiz not started")
        
        quiz = active_quizzes.get(username)
        if not quiz:
            raise HTTPException(status_code=404, detail="Quiz not found")
        
        current_idx = quiz['current_index']
        questions = quiz['questions']
        
        if current_idx >= len(questions):
            # Quiz completed
            return JSONResponse({
                'status': 'completed',
                'score': client['score'],
                'total': len(questions)
            })
        
        question = questions[current_idx]
        seq = random.randint(1, 1_000_000)
        
        client['last_seen'] = time.time()
        
        return JSONResponse({
            'status': 'ok',
            'seq': seq,
            'index': current_idx + 1,
            'question': question['question'],
            'options': question['options'],
            'time': QUESTION_TIME
        })
        
    except HTTPException:
        raise
    except Exception as e:
        logging.exception("Get question error: %s", e)
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/quiz/answer")
async def submit_answer(request: Request):
    """Submit answer for current question."""
    try:
        session_id = request.headers.get("X-Session-ID")
        if not session_id:
            raise HTTPException(status_code=401, detail="Session ID required")
        
        username = sessions.get(session_id)
        if not username or username not in clients:
            raise HTTPException(status_code=401, detail="Invalid or expired session")
        
        data = await request.json()
        answer = data.get('answer')
        seq = data.get('seq')
        
        if answer is None:
            raise HTTPException(status_code=400, detail="Answer required")
        
        client = clients[username]
        if not client['started']:
            raise HTTPException(status_code=400, detail="Quiz not started")
        
        quiz = active_quizzes.get(username)
        if not quiz:
            raise HTTPException(status_code=404, detail="Quiz not found")
        
        current_idx = quiz['current_index']
        questions = quiz['questions']
        
        if current_idx >= len(questions):
            raise HTTPException(status_code=400, detail="Quiz already completed")
        
        question = questions[current_idx]
        correct = (answer.upper() == question.get('answer', '').upper())
        
        if correct:
            client['score'] += 1
            scores[username] = client['score']
        
        # Move to next question
        quiz['current_index'] += 1
        client['last_seen'] = time.time()
        
        result = {
            'status': 'correct' if correct else 'wrong',
            'seq': seq,
            'correct_answer': question.get('answer') if not correct else None,
            'score': client['score'],
            'current_question': quiz['current_index'] + 1,
            'total_questions': len(questions)
        }
        
        logging.info("User %s answered question %d: %s (correct: %s)", 
                    username, current_idx + 1, answer, correct)
        
        return JSONResponse(result)
        
    except HTTPException:
        raise
    except Exception as e:
        logging.exception("Submit answer error: %s", e)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/quiz/leaderboard")
async def get_leaderboard():
    """Get current leaderboard."""
    try:
        leaderboard = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        return JSONResponse({
            'status': 'ok',
            'leaderboard': leaderboard
        })
    except Exception as e:
        logging.exception("Get leaderboard error: %s", e)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/quiz/stream")
async def stream_quiz(session_id: str = Header(..., alias="X-Session-ID")):
    """Server-Sent Events stream for real-time quiz updates."""
    username = sessions.get(session_id)
    if not username or username not in clients:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    
    client = clients[username]
    if not client['started']:
        raise HTTPException(status_code=400, detail="Quiz not started")
    
    async def event_generator():
        try:
            quiz = active_quizzes.get(username)
            if not quiz:
                yield f"data: {json.dumps({'type': 'error', 'message': 'Quiz not found'})}\n\n"
                return
            
            questions = quiz['questions']
            current_idx = 0
            
            while current_idx < len(questions):
                question = questions[current_idx]
                seq = random.randint(1, 1_000_000)
                
                question_data = {
                    'type': 'question',
                    'seq': seq,
                    'index': current_idx + 1,
                    'question': question['question'],
                    'options': question['options'],
                    'time': QUESTION_TIME
                }
                
                yield f"data: {json.dumps(question_data)}\n\n"
                
                # Wait for answer or timeout
                start_time = time.time()
                answered = False
                
                while time.time() - start_time < QUESTION_TIME and not answered:
                    await asyncio.sleep(0.5)
                    # Check if answer was submitted (simplified - in real implementation, 
                    # you'd check a shared state)
                    if quiz['current_index'] > current_idx:
                        answered = True
                
                current_idx = quiz['current_index']
            
            # Quiz completed
            final_score = client['score']
            scores[username] = final_score
            leaderboard = sorted(scores.items(), key=lambda x: x[1], reverse=True)
            
            completion_data = {
                'type': 'completed',
                'score': final_score,
                'total': len(questions),
                'leaderboard': leaderboard
            }
            
            yield f"data: {json.dumps(completion_data)}\n\n"
            
        except Exception as e:
            logging.exception("SSE stream error: %s", e)
            error_data = {'type': 'error', 'message': str(e)}
            yield f"data: {json.dumps(error_data)}\n\n"
    
    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return JSONResponse({'status': 'ok', 'timestamp': datetime.now().isoformat()})

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
            ip_obj = ipaddress.IPv4Address(HOST)
            san_list.append(x509.IPAddress(ip_obj))
        except ValueError:
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
    import asyncio
    
    # Create SSL context if using SSL
    ssl_context = None
    if USE_SSL:
        try:
            os.makedirs('ssl', exist_ok=True)
            if not os.path.exists(SSL_CERT_FILE) or not os.path.exists(SSL_KEY_FILE):
                logging.warning("SSL certificate files not found. Generating self-signed certificate...")
                generate_self_signed_cert()
            
            ssl_context = (SSL_CERT_FILE, SSL_KEY_FILE)
            logging.info("SSL enabled. Using certificate: %s", SSL_CERT_FILE)
        except Exception as e:
            logging.error("Failed to setup SSL: %s. Continuing without SSL...", e)
            ssl_context = None
    
    protocol = "https" if ssl_context else "http"
    logging.info("HTTP server starting on %s://%s:%s", protocol, HOST, PORT)
    print(f"✅ HTTP server started on {protocol}://{HOST}:{PORT}")
    if ssl_context:
        print(f"   🔒 HTTPS/SSL enabled")
    print(f"   Configure Apache to proxy HTTP requests to this server")
    
    uvicorn.run(
        app,
        host=HOST,
        port=PORT,
        ssl_keyfile=SSL_KEY_FILE if ssl_context else None,
        ssl_certfile=SSL_CERT_FILE if ssl_context else None,
        log_level="info"
    )
