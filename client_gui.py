import json
import time
import threading
import logging
import os
import requests
from requests.exceptions import RequestException
from exceptions import QuizError, NetworkError, DataFormatError, AuthError
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from datetime import datetime

HOST = '127.0.0.1'  # Replace with your server IP or Apache server
PORT = 8080
USE_SSL = True  # Enable HTTPS/SSL support
BASE_URL = f'https://{HOST}:{PORT}' if USE_SSL else f'http://{HOST}:{PORT}'
QUESTION_TIME = 15

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
file_handler = logging.FileHandler(os.path.join(LOG_DIR, "client.log"))
file_handler.setFormatter(StatusCodeFormatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(file_handler)

# Create session with SSL verification disabled for self-signed certificates
session = requests.Session()
if USE_SSL:
    session.verify = False
    # Disable SSL warnings for self-signed certificates
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class QuizClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Live Quiz Client")
        self.root.geometry("800x700")
        self.root.configure(bg='#f0f0f0')
        
        # State variables
        self.session_id = None
        self.username = None
        self.current_question = None
        self.current_seq = None
        self.quiz_started = False
        self.score = 0
        self.total_questions = 0
        self.current_question_index = 0
        self.timer_thread = None
        self.timer_running = False
        
        # Style configuration
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'), background='#f0f0f0')
        style.configure('Heading.TLabel', font=('Arial', 12, 'bold'), background='#f0f0f0')
        style.configure('Question.TLabel', font=('Arial', 11), background='#ffffff', wraplength=700)
        
        self.create_widgets()
        
    def create_widgets(self):
        # Title
        title_frame = tk.Frame(self.root, bg='#2c3e50', height=60)
        title_frame.pack(fill=tk.X)
        title_frame.pack_propagate(False)
        
        title_label = tk.Label(
            title_frame,
            text="🧠 Live Quiz Client",
            font=('Arial', 20, 'bold'),
            bg='#2c3e50',
            fg='white'
        )
        title_label.pack(pady=15)
        
        # Main container
        main_frame = tk.Frame(self.root, bg='#f0f0f0', padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Login frame
        self.login_frame = tk.Frame(main_frame, bg='#ffffff', relief=tk.RAISED, bd=2, padx=30, pady=30)
        self.login_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        login_title = tk.Label(
            self.login_frame,
            text="Login",
            font=('Arial', 18, 'bold'),
            bg='#ffffff',
            fg='#2c3e50'
        )
        login_title.pack(pady=(0, 20))
        
        # Server configuration
        config_frame = tk.Frame(self.login_frame, bg='#ffffff')
        config_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(config_frame, text="Server URL:", font=('Arial', 10), bg='#ffffff').pack(side=tk.LEFT, padx=5)
        self.server_url_var = tk.StringVar(value=BASE_URL)
        server_entry = tk.Entry(config_frame, textvariable=self.server_url_var, width=40, font=('Arial', 10))
        server_entry.pack(side=tk.LEFT, padx=5)
        
        # Username
        username_frame = tk.Frame(self.login_frame, bg='#ffffff')
        username_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(username_frame, text="Username:", font=('Arial', 11), bg='#ffffff', width=12, anchor='w').pack(side=tk.LEFT)
        self.username_entry = tk.Entry(username_frame, font=('Arial', 11), width=30)
        self.username_entry.pack(side=tk.LEFT, padx=5)
        self.username_entry.focus()
        
        # Password
        password_frame = tk.Frame(self.login_frame, bg='#ffffff')
        password_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(password_frame, text="Password:", font=('Arial', 11), bg='#ffffff', width=12, anchor='w').pack(side=tk.LEFT)
        self.password_entry = tk.Entry(password_frame, show='*', font=('Arial', 11), width=30)
        self.password_entry.pack(side=tk.LEFT, padx=5)
        self.password_entry.bind('<Return>', lambda e: self.login())
        
        # Login button
        login_btn = tk.Button(
            self.login_frame,
            text="Login",
            command=self.login,
            font=('Arial', 12, 'bold'),
            bg='#3498db',
            fg='white',
            activebackground='#2980b9',
            activeforeground='white',
            relief=tk.FLAT,
            padx=30,
            pady=10,
            cursor='hand2'
        )
        login_btn.pack(pady=20)
        
        # Status label
        self.status_label = tk.Label(
            self.login_frame,
            text="",
            font=('Arial', 10),
            bg='#ffffff',
            fg='#7f8c8d'
        )
        self.status_label.pack(pady=5)
        
        # Quiz frame (hidden initially)
        self.quiz_frame = tk.Frame(main_frame, bg='#f0f0f0')
        
        # Score and timer frame
        score_frame = tk.Frame(self.quiz_frame, bg='#34495e', relief=tk.RAISED, bd=2)
        score_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.score_label = tk.Label(
            score_frame,
            text="Score: 0/0",
            font=('Arial', 14, 'bold'),
            bg='#34495e',
            fg='white'
        )
        self.score_label.pack(side=tk.LEFT, padx=20, pady=10)
        
        self.timer_label = tk.Label(
            score_frame,
            text="Time: 0s",
            font=('Arial', 14, 'bold'),
            bg='#34495e',
            fg='#f39c12'
        )
        self.timer_label.pack(side=tk.RIGHT, padx=20, pady=10)
        
        # Question frame
        question_container = tk.Frame(self.quiz_frame, bg='#ffffff', relief=tk.RAISED, bd=2)
        question_container.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.question_label = tk.Label(
            question_container,
            text="Waiting for question...",
            font=('Arial', 14, 'bold'),
            bg='#ffffff',
            fg='#2c3e50',
            wraplength=700,
            justify=tk.LEFT
        )
        self.question_label.pack(pady=20, padx=20, anchor='w')
        
        # Options frame
        self.options_frame = tk.Frame(question_container, bg='#ffffff')
        self.options_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.option_buttons = []
        for i in range(4):
            btn = tk.Button(
                self.options_frame,
                text="",
                font=('Arial', 12),
                bg='#ecf0f1',
                fg='#2c3e50',
                activebackground='#bdc3c7',
                activeforeground='#2c3e50',
                relief=tk.RAISED,
                bd=2,
                padx=20,
                pady=15,
                cursor='hand2',
                command=lambda idx=i: self.select_answer(idx)
            )
            btn.pack(fill=tk.X, pady=5)
            self.option_buttons.append(btn)
        
        # Result label
        self.result_label = tk.Label(
            question_container,
            text="",
            font=('Arial', 12, 'bold'),
            bg='#ffffff',
            fg='#27ae60'
        )
        self.result_label.pack(pady=10)
        
        # Leaderboard frame
        leaderboard_frame = tk.Frame(self.quiz_frame, bg='#ffffff', relief=tk.RAISED, bd=2)
        leaderboard_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        leaderboard_title = tk.Label(
            leaderboard_frame,
            text="🏆 Leaderboard",
            font=('Arial', 14, 'bold'),
            bg='#ffffff',
            fg='#2c3e50'
        )
        leaderboard_title.pack(pady=10)
        
        self.leaderboard_text = scrolledtext.ScrolledText(
            leaderboard_frame,
            height=8,
            font=('Arial', 10),
            bg='#f8f9fa',
            fg='#2c3e50',
            relief=tk.FLAT,
            bd=0
        )
        self.leaderboard_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        self.leaderboard_text.config(state=tk.DISABLED)
        
    def update_status(self, message, color='#7f8c8d'):
        """Update status label."""
        self.status_label.config(text=message, fg=color)
        self.root.update()
        
    def login(self):
        """Handle login."""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        base_url = self.server_url_var.get().strip()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password")
            return
        
        if not base_url:
            messagebox.showerror("Error", "Please enter server URL")
            return
        
        self.update_status("Connecting...", '#3498db')
        
        # Update session base URL
        global BASE_URL
        BASE_URL = base_url
        
        try:
            response = session.post(
                f"{BASE_URL}/api/auth",
                json={'username': username, 'password': password},
                timeout=5
            )
            response.raise_for_status()
            data = response.json()
            
            if data.get('status') == 'ok':
                self.session_id = data.get('session_id')
                self.username = username
                logging.info("Authenticated as %s, session_id: %s", username, self.session_id)
                
                # Hide login, show quiz
                self.login_frame.pack_forget()
                self.quiz_frame.pack(fill=tk.BOTH, expand=True)
                
                # Start quiz
                self.start_quiz()
            else:
                messagebox.showerror("Authentication Failed", "Invalid username or password")
                self.update_status("Authentication failed", '#e74c3c')
                logging.warning("Authentication failed for %s", username)
                
        except RequestException as e:
            messagebox.showerror("Connection Error", f"Failed to connect to server:\n{str(e)}")
            self.update_status("Connection failed", '#e74c3c')
            logging.error("Connection error: %s", e)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred:\n{str(e)}")
            self.update_status("Error occurred", '#e74c3c')
            logging.error("Login error: %s", e)
    
    def start_quiz(self):
        """Start quiz session."""
        try:
            response = session.get(
                f"{BASE_URL}/api/quiz/start",
                headers={'X-Session-ID': self.session_id},
                timeout=5
            )
            response.raise_for_status()
            data = response.json()
            
            if data.get('status') == 'ok':
                self.total_questions = data.get('total_questions', 0)
                self.quiz_started = True
                self.score = 0
                self.current_question_index = 0
                logging.info("Quiz started: %d questions", self.total_questions)
                
                # Start polling for questions
                self.poll_question()
                self.update_leaderboard()
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start quiz:\n{str(e)}")
            logging.error("Start quiz error: %s", e)
    
    def poll_question(self):
        """Poll for next question."""
        if not self.quiz_started:
            return
        
        try:
            response = session.get(
                f"{BASE_URL}/api/quiz/question",
                headers={'X-Session-ID': self.session_id},
                timeout=5
            )
            response.raise_for_status()
            data = response.json()
            
            if data.get('status') == 'completed':
                self.show_completion()
                return
            
            if data.get('status') == 'ok':
                self.current_question = data
                self.current_seq = data.get('seq')
                self.current_question_index = data.get('index', 0)
                
                self.display_question(data)
                self.start_timer(data.get('time', QUESTION_TIME))
                
        except Exception as e:
            logging.error("Poll question error: %s", e)
            self.root.after(1000, self.poll_question)
    
    def display_question(self, question_data):
        """Display question and options."""
        question = question_data.get('question', '')
        options = question_data.get('options', [])
        
        self.question_label.config(
            text=f"Question {self.current_question_index}/{self.total_questions}: {question}"
        )
        
        for i, option in enumerate(options):
            if i < len(self.option_buttons):
                self.option_buttons[i].config(text=option, state=tk.NORMAL)
        
        # Hide extra buttons
        for i in range(len(options), len(self.option_buttons)):
            self.option_buttons[i].config(text="", state=tk.DISABLED)
        
        self.result_label.config(text="")
        self.update_score()
    
    def start_timer(self, seconds):
        """Start countdown timer."""
        self.timer_running = True
        self.timer_seconds = seconds
        
        def countdown():
            while self.timer_running and self.timer_seconds > 0:
                self.timer_label.config(text=f"Time: {self.timer_seconds}s")
                time.sleep(1)
                self.timer_seconds -= 1
                if not self.timer_running:
                    break
            
            if self.timer_seconds == 0 and self.timer_running:
                # Timeout - submit empty answer
                self.submit_answer(None)
        
        self.timer_thread = threading.Thread(target=countdown, daemon=True)
        self.timer_thread.start()
    
    def select_answer(self, option_index):
        """Handle answer selection."""
        if not self.timer_running:
            return
        
        # Extract answer letter (A, B, C, or D)
        option_text = self.option_buttons[option_index].cget('text')
        if option_text:
            answer = option_text[0] if option_text[0].isalpha() else None
            self.submit_answer(answer)
    
    def submit_answer(self, answer):
        """Submit answer to server."""
        if not self.timer_running:
            return
        
        self.timer_running = False
        
        # Disable buttons
        for btn in self.option_buttons:
            btn.config(state=tk.DISABLED)
        
        try:
            response = session.post(
                f"{BASE_URL}/api/quiz/answer",
                headers={'X-Session-ID': self.session_id},
                json={'answer': answer, 'seq': self.current_seq},
                timeout=5
            )
            response.raise_for_status()
            result = response.json()
            
            status = result.get('status')
            if status == 'correct':
                self.result_label.config(text="✅ Correct!", fg='#27ae60')
                self.score = result.get('score', self.score)
            else:
                correct_answer = result.get('correct_answer', '')
                self.result_label.config(
                    text=f"❌ Wrong. Correct answer: {correct_answer}",
                    fg='#e74c3c'
                )
                self.score = result.get('score', self.score)
            
            self.update_score()
            logging.info("Answer submitted: %s (correct: %s)", answer, status == 'correct')
            
            # Wait a bit, then get next question
            self.root.after(2000, self.poll_question)
            self.update_leaderboard()
            
        except Exception as e:
            logging.error("Submit answer error: %s", e)
            messagebox.showerror("Error", f"Failed to submit answer:\n{str(e)}")
            self.root.after(2000, self.poll_question)
    
    def update_score(self):
        """Update score display."""
        self.score_label.config(text=f"Score: {self.score}/{self.current_question_index}")
    
    def update_leaderboard(self):
        """Update leaderboard display."""
        try:
            response = session.get(
                f"{BASE_URL}/api/quiz/leaderboard",
                timeout=5
            )
            response.raise_for_status()
            data = response.json()
            
            leaderboard = data.get('leaderboard', [])
            
            self.leaderboard_text.config(state=tk.NORMAL)
            self.leaderboard_text.delete(1.0, tk.END)
            
            if leaderboard:
                for i, (username, score) in enumerate(leaderboard, 1):
                    marker = "🥇" if i == 1 else "🥈" if i == 2 else "🥉" if i == 3 else "  "
                    self.leaderboard_text.insert(tk.END, f"{marker} {i}. {username}: {score} points\n")
            else:
                self.leaderboard_text.insert(tk.END, "No scores yet.\n")
            
            self.leaderboard_text.config(state=tk.DISABLED)
            
        except Exception as e:
            logging.error("Update leaderboard error: %s", e)
    
    def show_completion(self):
        """Show quiz completion message."""
        self.timer_running = False
        self.timer_label.config(text="Completed!")
        
        for btn in self.option_buttons:
            btn.config(state=tk.DISABLED)
        
        self.question_label.config(
            text=f"🎉 Quiz Completed!\n\nYour final score: {self.score}/{self.total_questions}",
            font=('Arial', 16, 'bold'),
            fg='#27ae60'
        )
        
        self.update_leaderboard()
        logging.info("Quiz completed with score %d/%d", self.score, self.total_questions)


def main():
    """Main entry point."""
    root = tk.Tk()
    app = QuizClientGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

