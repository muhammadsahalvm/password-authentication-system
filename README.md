# Password Authentication System - Web Version

A beautiful, secure web-based login and registration system using Flask and bcrypt password hashing.

## Features

✅ **Secure Authentication** - Uses bcrypt for password hashing  
✅ **User Registration** - Create new accounts with validation  
✅ **User Login** - Authenticate with stored credentials  
✅ **Dashboard** - Personalized user dashboard after login  
✅ **Session Management** - Secure session handling  
✅ **Responsive Design** - Works on desktop, tablet, and mobile  
✅ **Beautiful UI** - Modern gradient design with smooth animations  

## Project Structure

```
password_auth/
├── app.py                      # Flask application (main server)
├── auth.py                     # Authentication functions (password hashing/verification)
├── requirements.txt            # Python dependencies
├── users.json                  # User database (created automatically)
├── static/
│   └── style.css              # CSS styling
└── templates/
    ├── login.html             # Login page
    ├── register.html          # Registration page
    └── dashboard.html         # User dashboard
```

## Installation

<<<<<<< HEAD
=======
1. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```bash

>>>>>>> 4ad80b9d1681d2a8dcac070c67dd7d3cc142b572
## Running the Application

1. **Start the Flask server:**
   ```bash
   python app.py
   ```

2. **Open your browser and go to:**
   ```
   http://localhost:5000
   ```

3. **Register a new account or login with existing credentials**

## How It Works

- **Password Storage**: Passwords are hashed using bcrypt with salt before storing
- **User Database**: Users are stored in `users.json` with their hashed passwords
- **Session Management**: Flask sessions maintain user login state
- **Security**: Passwords are never stored in plain text

## Default Routes

| Route | Method | Purpose |
|-------|--------|---------|
| `/` | GET | Home page (redirects to login/dashboard) |
| `/login` | GET/POST | Login page and authentication |