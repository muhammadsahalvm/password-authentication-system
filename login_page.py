import tkinter as tk
from tkinter import messagebox, ttk
import json
import os
from auth import hash_password, verify_password, validate_password

# Users database file
USERS_DB = "users.json"

def load_users():
    """Load users from JSON file"""
    if os.path.exists(USERS_DB):
        with open(USERS_DB, "r") as f:
            return json.load(f)
    return {}

def save_users(users):
    """Save users to JSON file"""
    with open(USERS_DB, "w") as f:
        json.dump(users, f, indent=4, default=str)

def register_user(username, password):
    """Register a new user"""
    users = load_users()
    
    if username in users:
        messagebox.showerror("Registration Failed", "Username already exists!")
        return False
    
    # Validate password strength
    is_valid, message = validate_password(password)
    if not is_valid:
        messagebox.showerror("Registration Failed", message)
        return False
    
    hashed_password = hash_password(password)
    users[username] = hashed_password.hex()
    save_users(users)
    
    messagebox.showinfo("Success", f"User '{username}' registered successfully!")
    return True

def login_user(username, password):
    """Verify user login"""
    users = load_users()
    
    if username not in users:
        messagebox.showerror("Login Failed", "Username does not exist!")
        return False
    
    stored_hash = bytes.fromhex(users[username])
    if verify_password(password, stored_hash):
        messagebox.showinfo("Success", f"Welcome {username}! Login successful!")
        return True
    else:
        messagebox.showerror("Login Failed", "Incorrect password!")
        return False

class LoginApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Authentication System")
        self.root.geometry("400x350")
        self.root.resizable(False, False)
        
        # Set style
        self.root.configure(bg="#f0f0f0")
        
        self.current_frame = None
        self.show_login_page()
    
    def clear_frame(self):
        """Clear current frame"""
        if self.current_frame:
            self.current_frame.destroy()
        self.current_frame = tk.Frame(self.root, bg="#f0f0f0")
        self.current_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
    
    def show_login_page(self):
        """Display login page"""
        self.clear_frame()
        
        # Title
        title = tk.Label(
            self.current_frame,
            text="Login",
            font=("Arial", 24, "bold"),
            bg="#f0f0f0",
            fg="#333"
        )
        title.pack(pady=10)
        
        # Username
        tk.Label(
            self.current_frame,
            text="Username:",
            font=("Arial", 10),
            bg="#f0f0f0"
        ).pack(anchor=tk.W, pady=5)
        
        username_entry = tk.Entry(self.current_frame, font=("Arial", 10), width=35)
        username_entry.pack(pady=5)
        
        # Password
        tk.Label(
            self.current_frame,
            text="Password:",
            font=("Arial", 10),
            bg="#f0f0f0"
        ).pack(anchor=tk.W, pady=5)
        
        password_entry = tk.Entry(self.current_frame, font=("Arial", 10), width=35, show="*")
        password_entry.pack(pady=5)
        
        # Button frame
        button_frame = tk.Frame(self.current_frame, bg="#f0f0f0")
        button_frame.pack(pady=20)
        
        # Login button
        login_btn = tk.Button(
            button_frame,
            text="Login",
            font=("Arial", 10, "bold"),
            bg="#4CAF50",
            fg="white",
            width=12,
            command=lambda: login_user(username_entry.get(), password_entry.get())
        )
        login_btn.pack(side=tk.LEFT, padx=5)
        
        # Register button
        register_btn = tk.Button(
            button_frame,
            text="Register",
            font=("Arial", 10, "bold"),
            bg="#2196F3",
            fg="white",
            width=12,
            command=self.show_register_page
        )
        register_btn.pack(side=tk.LEFT, padx=5)
    
    def show_register_page(self):
        """Display registration page"""
        self.clear_frame()
        
        # Title
        title = tk.Label(
            self.current_frame,
            text="Register",
            font=("Arial", 24, "bold"),
            bg="#f0f0f0",
            fg="#333"
        )
        title.pack(pady=10)
        
        # Username
        tk.Label(
            self.current_frame,
            text="Username:",
            font=("Arial", 10),
            bg="#f0f0f0"
        ).pack(anchor=tk.W, pady=5)
        
        username_entry = tk.Entry(self.current_frame, font=("Arial", 10), width=35)
        username_entry.pack(pady=5)
        
        # Password
        tk.Label(
            self.current_frame,
            text="Password:",
            font=("Arial", 10),
            bg="#f0f0f0"
        ).pack(anchor=tk.W, pady=5)
        
        password_entry = tk.Entry(self.current_frame, font=("Arial", 10), width=35, show="*")
        password_entry.pack(pady=5)
        
        # Confirm Password
        tk.Label(
            self.current_frame,
            text="Confirm Password:",
            font=("Arial", 10),
            bg="#f0f0f0"
        ).pack(anchor=tk.W, pady=5)
        
        confirm_password_entry = tk.Entry(self.current_frame, font=("Arial", 10), width=35, show="*")
        confirm_password_entry.pack(pady=5)
        
        # Button frame
        button_frame = tk.Frame(self.current_frame, bg="#f0f0f0")
        button_frame.pack(pady=20)
        
        def register():
            if password_entry.get() != confirm_password_entry.get():
                messagebox.showerror("Registration Failed", "Passwords do not match!")
                return
            
            if register_user(username_entry.get(), password_entry.get()):
                self.show_login_page()
        
        # Register button
        register_btn = tk.Button(
            button_frame,
            text="Register",
            font=("Arial", 10, "bold"),
            bg="#4CAF50",
            fg="white",
            width=12,
            command=register
        )
        register_btn.pack(side=tk.LEFT, padx=5)
        
        # Back button
        back_btn = tk.Button(
            button_frame,
            text="Back to Login",
            font=("Arial", 10, "bold"),
            bg="#FF9800",
            fg="white",
            width=12,
            command=self.show_login_page
        )
        back_btn.pack(side=tk.LEFT, padx=5)

if __name__ == "__main__":
    root = tk.Tk()
    app = LoginApp(root)
    root.mainloop()
