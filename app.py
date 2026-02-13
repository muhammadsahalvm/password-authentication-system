from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import json
import os
from auth import hash_password, verify_password, validate_password
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'

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

def login_required(f):
    """Decorator to check if user is logged in"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    """Home page"""
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'success': False, 'message': 'Username and password required'})
        
        users = load_users()
        
        if username not in users:
            return jsonify({'success': False, 'message': 'Username does not exist'})
        
        try:
            stored_hash = bytes.fromhex(users[username])
            if verify_password(password, stored_hash):
                session['username'] = username
                return jsonify({'success': True, 'message': 'Login successful'})
            else:
                return jsonify({'success': False, 'message': 'Incorrect password'})
        except Exception as e:
            return jsonify({'success': False, 'message': 'Error verifying password'})
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registration page"""
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        confirm_password = data.get('confirm_password')
        
        if not username or not password or not confirm_password:
            return jsonify({'success': False, 'message': 'All fields required'})
        
        if password != confirm_password:
            return jsonify({'success': False, 'message': 'Passwords do not match'})
        
        # Validate password strength
        is_valid, validation_message = validate_password(password)
        if not is_valid:
            return jsonify({'success': False, 'message': validation_message})
        
        users = load_users()
        
        if username in users:
            return jsonify({'success': False, 'message': 'Username already exists'})
        
        try:
            hashed_password = hash_password(password)
            users[username] = hashed_password.hex()
            save_users(users)
            return jsonify({'success': True, 'message': 'Registration successful. Please login.'})
        except Exception as e:
            return jsonify({'success': False, 'message': f'Error: {str(e)}'})
    
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard for logged-in users"""
    return render_template('dashboard.html', username=session['username'])

@app.route('/logout')
def logout():
    """Logout user"""
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
