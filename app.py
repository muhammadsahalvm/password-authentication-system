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


def categorize_age(age):
    if age < 13:
        return "Child"
    elif 13 <= age <= 19:
        return "Teenager"
    elif 20 <= age <= 59:
        return "Adult"
    else:
        return "Senior"
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
            user_record = users[username]
            # Support legacy format where value is just the hex password string
            if isinstance(user_record, str):
                stored_hash = bytes.fromhex(user_record)
                age_category = None
            else:
                stored_hash = bytes.fromhex(user_record.get('password'))
                age_category = user_record.get('age_category')

            if verify_password(password, stored_hash):
                session['username'] = username
                if age_category:
                    session['age_category'] = age_category
                return jsonify({'success': True, 'message': 'Login successful', 'age_category': age_category})
            else:
                return jsonify({'success': False, 'message': 'Incorrect password'})
        except Exception:
            return jsonify({'success': False, 'message': 'Error verifying password'})
            return jsonify({'success': False, 'message': 'Error verifying password'})
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registration page"""
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')

        age = data.get('age')
        hobby = data.get('hobby').strip() if data.get('hobby') else ""
        # age will be validated later
        password = data.get('password')
        confirm_password = data.get('confirm_password')
        
        if not username or not password or not confirm_password:
            return jsonify({'success': False, 'message': 'All fields required'})
        

        # Validate and normalize age
        if age is None:
            return jsonify({'success': False, 'message': 'Age is required'})
        try:
            age_int = int(age)
        except (TypeError, ValueError):
            return jsonify({'success': False, 'message': 'Age must be a number'})

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

            # Store richer user record including age and category
            users[username] = {
                'password': hashed_password.hex(),
                'age': age_int,
                'age_category': categorize_age(age_int),
                'hobby': hobby
            }
            save_users(users)
            return jsonify({'success': True, 'message': 'Registration successful. Please login.'})
        except Exception as e:
            return jsonify({'success': False, 'message': f'Error: {str(e)}'})
    
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard for logged-in users"""

    users = load_users()
    username = session['username']
    
    user_record = users.get(username)

    age_category = None
    hobby = None

    if isinstance(user_record, dict):
        age_category = user_record.get('age_category')
        hobby = user_record.get('hobby')

    return render_template(
        'dashboard.html',
        username=username,
        age_category=age_category,
        hobby=hobby
    )
@app.route('/logout')
def logout():
    """Logout user"""
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
