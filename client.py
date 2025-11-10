import json
import time
import random
import logging
import os
import ssl
import requests
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from threading import Thread, Event
import sys
from requests.exceptions import RequestException, ConnectionError, Timeout
from exceptions import QuizError, NetworkError, DataFormatError, AuthError

HOST = '127.0.0.1'  # Replace with your server IP or Apache server
PORT = 8080
USE_SSL = True  # Enable HTTPS/SSL support
BASE_URL = f'https://{HOST}:{PORT}' if USE_SSL else f'http://{HOST}:{PORT}'
QUESTION_TIME = 15
RECONNECT_BACKOFF = [1, 2, 5, 10]

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

# logging
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

# Create logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Create file handler with custom formatter
file_handler = logging.FileHandler(os.path.join(LOG_DIR, "client.log"))
file_handler.setFormatter(StatusCodeFormatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(file_handler)

# Clear client log on startup
try:
    open(os.path.join(LOG_DIR, "client.log"), 'w').close()
except Exception:
    pass

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
        self.root.geometry("800x600")
        self.root.configure(bg='#f0f0f0')
        
        # Quiz state variables
        self.session_id = None
        self.username = None
        self.quiz_active = False
        self.current_question = None
        self.answer_buttons = []
        self.timer_event = None
        self.time_left = 0
        self.stop_event = Event()
        
        self.setup_gui()
        
    def setup_gui(self):
        """Setup the GUI components"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(3, weight=1)
        
        # Login frame
        login_frame = ttk.LabelFrame(main_frame, text="Login", padding="10")
        login_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        login_frame.columnconfigure(1, weight=1)
        
        ttk.Label(login_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.username_entry = ttk.Entry(login_frame, width=20)
        self.username_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        ttk.Label(login_frame, text="Password:").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        self.password_entry = ttk.Entry(login_frame, width=20, show="*")
        self.password_entry.grid(row=0, column=3, sticky=(tk.W, tk.E), padx=(0, 10))
        
        self.login_button = ttk.Button(login_frame, text="Login", command=self.login)
        self.login_button.grid(row=0, column=4, padx=(10, 0))
        
        # Bind Enter key to login
        self.username_entry.bind('<Return>', lambda e: self.login())
        self.password_entry.bind('<Return>', lambda e: self.login())
        
        # Status frame
        status_frame = ttk.LabelFrame(main_frame, text="Status", padding="10")
        status_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        status_frame.columnconfigure(0, weight=1)
        
        self.status_var = tk.StringVar(value="Not connected")
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var, foreground="red")
        self.status_label.grid(row=0, column=0, sticky=tk.W)
        
        # Timer label
        self.timer_var = tk.StringVar(value="Time: --")
        self.timer_label = ttk.Label(status_frame, textvariable=self.timer_var, font=('Arial', 12, 'bold'))
        self.timer_label.grid(row=0, column=1, sticky=tk.E)
        
        # Score label
        self.score_var = tk.StringVar(value="Score: 0/0")
        self.score_label = ttk.Label(status_frame, textvariable=self.score_var)
        self.score_label.grid(row=0, column=2, sticky=tk.E, padx=(10, 0))
        
        # Question frame
        self.question_frame = ttk.LabelFrame(main_frame, text="Question", padding="15")
        self.question_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        self.question_frame.columnconfigure(0, weight=1)
        
        self.question_var = tk.StringVar(value="Please login and start the quiz")
        self.question_label = ttk.Label(self.question_frame, textvariable=self.question_var, 
                                      wraplength=700, justify=tk.LEFT, font=('Arial', 11))
        self.question_label.grid(row=0, column=0, sticky=tk.W)
        
        # Options frame
        self.options_frame = ttk.Frame(self.question_frame)
        self.options_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(10, 0))
        self.options_frame.columnconfigure(0, weight=1)
        
        # Control buttons frame
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        control_frame.columnconfigure(0, weight=1)
        
        self.start_button = ttk.Button(control_frame, text="Start Quiz", command=self.start_quiz, state=tk.DISABLED)
        self.start_button.grid(row=0, column=0, padx=(0, 5))
        
        self.leaderboard_button = ttk.Button(control_frame, text="Show Leaderboard", 
                                           command=self.show_leaderboard, state=tk.DISABLED)
        self.leaderboard_button.grid(row=0, column=1, padx=5)
        
        # Log/Output frame
        output_frame = ttk.LabelFrame(main_frame, text="Activity Log", padding="5")
        output_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(4, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(output_frame, height=10, width=80, state=tk.DISABLED)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Initially hide question frame
        self.hide_question()
        
    def hide_question(self):
        """Hide question and options"""
        self.question_frame.grid_remove()
        
    def show_question(self):
        """Show question frame"""
        self.question_frame.grid()
        
    def log_message(self, message, color="black"):
        """Add message to log area"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"{time.strftime('%H:%M:%S')} - {message}\n", color)
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
        
        # Also log to file
        logging.info(message)
        
    def set_status(self, message, is_error=False):
        """Update status label"""
        self.status_var.set(message)
        self.status_label.configure(foreground="red" if is_error else "green")
        
    def update_timer(self, time_left):
        """Update timer display"""
        self.time_left = time_left
        self.timer_var.set(f"Time: {time_left}s")
        
    def start_timer(self, duration):
        """Start countdown timer"""
        self.update_timer(duration)
        if self.timer_event:
            self.root.after_cancel(self.timer_event)
        self.timer_event = self.root.after(1000, self._timer_tick, duration)
        
    def _timer_tick(self, time_left):
        """Timer tick handler"""
        if time_left <= 0 or not self.quiz_active:
            return
            
        self.update_timer(time_left)
        self.timer_event = self.root.after(1000, self._timer_tick, time_left - 1)
        
    def stop_timer(self):
        """Stop the timer"""
        if self.timer_event:
            self.root.after_cancel(self.timer_event)
            self.timer_event = None
            
    def clear_options(self):
        """Clear answer options"""
        for button in self.answer_buttons:
            button.destroy()
        self.answer_buttons = []
        
    def create_option_buttons(self, options):
        """Create buttons for answer options"""
        self.clear_options()
        
        for i, option in enumerate(options):
            # Create a styled button for each option
            btn = tk.Button(self.options_frame, text=option, font=('Arial', 10),
                           command=lambda opt=option: self.submit_answer_gui(opt),
                           bg='#e0e0e0', activebackground='#d0d0d0',
                           relief=tk.RAISED, bd=2, padx=10, pady=5,
                           wraplength=600, justify=tk.LEFT)
            btn.grid(row=i, column=0, sticky=(tk.W, tk.E), pady=2)
            self.answer_buttons.append(btn)
            
    def submit_answer_gui(self, answer):
        """Submit answer from GUI button"""
        if not self.quiz_active or not self.current_question:
            return
            
        # Extract just the answer letter (A, B, C, D)
        answer_letter = answer[0] if answer and len(answer) > 2 else answer
        self.submit_answer(answer_letter)
        
    def login(self):
        """Handle login"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
            
        # Disable login button during attempt
        self.login_button.config(state=tk.DISABLED)
        self.log_message(f"Attempting to login as {username}...")
        
        # Run authentication in thread
        Thread(target=self._authenticate_thread, args=(username, password), daemon=True).start()
        
    def _authenticate_thread(self, username, password):
        """Authentication in separate thread"""
        try:
            session_id = self.authenticate(username, password)
            self.username = username
            self.session_id = session_id
            
            # Update GUI in main thread
            self.root.after(0, self._login_success, username)
            
        except Exception as e:
            self.root.after(0, self._login_failed, str(e))
            
    def _login_success(self, username):
        """Handle successful login"""
        self.set_status(f"Connected as {username}")
        self.start_button.config(state=tk.NORMAL)
        self.leaderboard_button.config(state=tk.NORMAL)
        self.login_button.config(state=tk.DISABLED)
        self.log_message(f"✅ Successfully logged in as {username}")
        messagebox.showinfo("Success", f"Logged in successfully as {username}")
        
    def _login_failed(self, error_msg):
        """Handle failed login"""
        self.set_status("Login failed", True)
        self.login_button.config(state=tk.NORMAL)
        self.log_message(f"❌ Login failed: {error_msg}")
        messagebox.showerror("Login Failed", f"Authentication failed: {error_msg}")
        
    def start_quiz(self):
        """Start the quiz"""
        if not self.session_id:
            messagebox.showerror("Error", "Please login first")
            return
            
        self.start_button.config(state=tk.DISABLED)
        self.quiz_active = True
        self.log_message("Starting quiz...")
        
        # Run quiz in separate thread
        Thread(target=self._run_quiz_thread, daemon=True).start()
        
    def _run_quiz_thread(self):
        """Run quiz in separate thread"""
        try:
            self.run_quiz_gui()
        except Exception as e:
            self.root.after(0, self._quiz_error, str(e))
            
    def _quiz_error(self, error_msg):
        """Handle quiz error"""
        self.quiz_active = False
        self.stop_timer()
        self.set_status("Quiz error", True)
        self.start_button.config(state=tk.NORMAL)
        self.log_message(f"❌ Quiz error: {error_msg}")
        messagebox.showerror("Quiz Error", f"An error occurred: {error_msg}")
        
    def show_leaderboard(self):
        """Show leaderboard"""
        if not self.session_id:
            messagebox.showerror("Error", "Please login first")
            return
            
        Thread(target=self._get_leaderboard_thread, daemon=True).start()
        
    def _get_leaderboard_thread(self):
        """Get leaderboard in separate thread"""
        try:
            leaderboard_data = self.get_leaderboard()
            self.root.after(0, self._display_leaderboard, leaderboard_data)
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to get leaderboard: {e}"))
            
    def _display_leaderboard(self, leaderboard_data):
        """Display leaderboard in new window"""
        leaderboard = leaderboard_data.get('leaderboard', [])
        
        # Create new window
        leaderboard_window = tk.Toplevel(self.root)
        leaderboard_window.title("Leaderboard")
        leaderboard_window.geometry("300x400")
        
        # Create treeview
        tree = ttk.Treeview(leaderboard_window, columns=('Rank', 'Username', 'Score'), show='headings')
        tree.heading('Rank', text='Rank')
        tree.heading('Username', text='Username')
        tree.heading('Score', text='Score')
        
        # Add data
        for i, (username, score) in enumerate(leaderboard, 1):
            tree.insert('', tk.END, values=(i, username, score))
            
        tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
    # Original API methods adapted for GUI
    def authenticate(self, username, password):
        """Authenticate user and return session ID."""
        try:
            response = session.post(
                f"{BASE_URL}/api/auth",
                json={'username': username, 'password': password},
                timeout=5
            )
            response.raise_for_status()
            data = response.json()
            
            if data.get('status') == 'ok':
                session_id = data.get('session_id')
                logging.info("Authenticated as %s, session_id: %s", username, session_id)
                return session_id
            else:
                raise AuthError("Authentication failed")
                
        except RequestException as e:
            raise NetworkError(f"Failed to authenticate: {e}") from e
        except Exception as e:
            if isinstance(e, (AuthError, NetworkError)):
                raise
            raise AuthError(f"Authentication error: {e}") from e

    def start_quiz_gui(self):
        """Start quiz session for GUI."""
        try:
            response = session.get(
                f"{BASE_URL}/api/quiz/start",
                headers={'X-Session-ID': self.session_id},
                timeout=5
            )
            response.raise_for_status()
            data = response.json()
            
            if data.get('status') == 'ok':
                self.root.after(0, self.log_message, 
                               f"Quiz started: {data.get('total_questions')} questions, {data.get('question_time')} seconds per question")
                return data
            else:
                raise QuizError("Failed to start quiz")
                
        except RequestException as e:
            raise NetworkError(f"Failed to start quiz: {e}") from e
        except Exception as e:
            if isinstance(e, (QuizError, NetworkError)):
                raise
            raise QuizError(f"Start quiz error: {e}") from e

    def get_question(self):
        """Get current question."""
        try:
            response = session.get(
                f"{BASE_URL}/api/quiz/question",
                headers={'X-Session-ID': self.session_id},
                timeout=5
            )
            response.raise_for_status()
            data = response.json()
            
            if data.get('status') == 'completed':
                return None  # Quiz completed
            
            return data
                
        except RequestException as e:
            raise NetworkError(f"Failed to get question: {e}") from e
        except Exception as e:
            if isinstance(e, NetworkError):
                raise
            raise NetworkError(f"Get question error: {e}") from e

    def submit_answer(self, answer):
        """Submit answer for current question."""
        if not self.current_question:
            return
            
        try:
            response = session.post(
                f"{BASE_URL}/api/quiz/answer",
                headers={'X-Session-ID': self.session_id},
                json={'answer': answer, 'seq': self.current_question.get('seq')},
                timeout=5
            )
            response.raise_for_status()
            result = response.json()
            
            # Update GUI with result
            self.root.after(0, self._handle_answer_result, result, answer)
                
        except RequestException as e:
            self.root.after(0, self.log_message, f"❌ Failed to submit answer: {e}")
        except Exception as e:
            self.root.after(0, self.log_message, f"❌ Submit answer error: {e}")

    def _handle_answer_result(self, result, submitted_answer):
        """Handle answer submission result"""
        if result.get('status') == 'correct':
            self.log_message("✅ Correct!")
        else:
            correct_answer = result.get('correct_answer')
            self.log_message(f"❌ Wrong. Correct answer: {correct_answer}")
        
        current_score = result.get('score', 0)
        current_index = self.current_question.get('index', 0)
        self.score_var.set(f"Score: {current_score}/{current_index}")
        self.log_message(f"Current score: {current_score}/{current_index}")

    def get_leaderboard(self):
        """Get current leaderboard."""
        try:
            response = session.get(
                f"{BASE_URL}/api/quiz/leaderboard",
                timeout=5
            )
            response.raise_for_status()
            return response.json()
                
        except RequestException as e:
            raise NetworkError(f"Failed to get leaderboard: {e}") from e
        except Exception as e:
            if isinstance(e, NetworkError):
                raise
            raise NetworkError(f"Get leaderboard error: {e}") from e

    def run_quiz_gui(self):
        """Run the quiz with GUI updates."""
        try:
            # Start quiz
            quiz_info = self.start_quiz_gui()
            total_questions = quiz_info.get('total_questions', 0)
            question_time = quiz_info.get('question_time', QUESTION_TIME)
            
            self.root.after(0, self.set_status, "Quiz in progress...")
            self.root.after(0, self.log_message, 
                          f"✅ Quiz started! {total_questions} questions, {question_time} seconds per question")
            
            while self.quiz_active and not self.stop_event.is_set():
                # Get current question
                question_data = self.get_question()
                
                if question_data is None:
                    # Quiz completed
                    self.root.after(0, self._quiz_completed)
                    break
                
                if question_data.get('status') != 'ok':
                    self.root.after(0, self.log_message, f"Unexpected question status: {question_data.get('status')}")
                    break
                
                # Update current question
                self.current_question = question_data
                seq = question_data.get('seq')
                index = question_data.get('index')
                question = question_data.get('question')
                options = question_data.get('options', [])
                
                # Update GUI with question
                self.root.after(0, self._display_question, index, total_questions, question, options, question_time)
                
                # Wait for answer submission or timeout
                self.stop_event.clear()
                self.stop_event.wait(question_time)
                
                # If time's up and no answer submitted, submit empty answer
                if not self.stop_event.is_set():
                    self.root.after(0, self.log_message, "⏰ Time's up!")
                    self.submit_answer(None)
                
                time.sleep(1)  # Brief pause before next question
            
            # Get final leaderboard
            if not self.stop_event.is_set():
                leaderboard_data = self.get_leaderboard()
                self.root.after(0, self._display_final_leaderboard, leaderboard_data, 
                              self.current_question.get('score', 0) if self.current_question else 0, 
                              total_questions)
                
        except Exception as e:
            self.root.after(0, self._quiz_error, str(e))

    def _display_question(self, index, total_questions, question, options, question_time):
        """Display question in GUI"""
        self.show_question()
        self.question_var.set(f"Question {index}/{total_questions}: {question}")
        self.create_option_buttons(options)
        self.start_timer(question_time)
        self.log_message(f"Question {index}/{total_questions}: {question}")

    def _quiz_completed(self):
        """Handle quiz completion"""
        self.quiz_active = False
        self.stop_timer()
        self.set_status("Quiz completed")
        self.hide_question()
        self.clear_options()
        self.log_message("🎉 Quiz completed!")

    def _display_final_leaderboard(self, leaderboard_data, final_score, total_questions):
        """Display final leaderboard"""
        leaderboard = leaderboard_data.get('leaderboard', [])
        
        self.log_message("\n🏆 Final Leaderboard:")
        for username, score in leaderboard:
            self.log_message(f"  {username}: {score}")
        
        self.log_message(f"🎯 Your final score: {final_score}/{total_questions}")
        self.start_button.config(state=tk.NORMAL)
        
        # Show final results in message box
        messagebox.showinfo("Quiz Completed", 
                          f"Quiz completed!\nYour final score: {final_score}/{total_questions}")

    def on_closing(self):
        """Handle window closing"""
        self.quiz_active = False
        self.stop_event.set()
        self.stop_timer()
        self.root.destroy()

def main():
    """Main client logic with GUI"""
    root = tk.Tk()
    app = QuizClientGUI(root)
    
    # Handle window closing
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    
    # Center the window
    root.eval('tk::PlaceWindow . center')
    
    root.mainloop()

if __name__ == "__main__":
    main()