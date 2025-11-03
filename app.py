"""
Flask application for file encryption/decryption using chess-based encoding.
Main application entry point with all routes and handlers.
"""

from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session, jsonify
import os
import time
import random
import threading
from dotenv import load_dotenv

# Import our custom modules
from user_management import load_users, save_users
from email_utils import send_otp_email
from file_processor import process_encryption, process_decryption

app = Flask(__name__)

# Global variable for progress tracking
progress_data = {}

# Load environment variables
load_dotenv()

app.secret_key = os.getenv('SECRET_KEY', os.urandom(24))

# Admin login credentials
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT"))
SMTP_EMAIL = os.getenv("SMTP_EMAIL")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

# Load users database
users_db = load_users()


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Handle user signup and send OTP for verification."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        # Check if username already exists
        if username in users_db:
            flash('Username already taken. Please choose another.')
            return redirect(url_for('signup'))

        # Send OTP and store user data temporarily in session
        otp = send_otp_email(email, SMTP_SERVER, SMTP_PORT, SMTP_EMAIL, SMTP_PASSWORD)
        if otp is not None:
            session['otp'] = otp
            session['temp_user'] = {'username': username, 'password': password, 'email': email}
            return redirect(url_for('verify_signup_otp'))
        else:
            flash('Failed to send OTP. Please try again.')
            return redirect(url_for('signup'))

    return render_template('signup.html')


@app.route('/verify_signup_otp', methods=['GET', 'POST'])
def verify_signup_otp():
    """Verify OTP during signup process."""
    if request.method == 'POST':
        entered_otp = request.form['otp']
        
        # Retrieve and remove OTP from session immediately after reading
        stored_otp = session.pop('otp', None)
        
        if stored_otp is not None and int(entered_otp) == stored_otp:
            # OTP is correct, save the user in the database
            temp_user = session.pop('temp_user', None)
            if temp_user:
                users_db[temp_user['username']] = {
                    'password': temp_user['password'],
                    'email': temp_user['email']
                }
                save_users(users_db)
                flash('Signup successful! Please log in.')
                return redirect(url_for('login'))
            else:
                flash('Session expired. Please try signing up again.')
                return redirect(url_for('signup'))
        else:
            flash('Invalid OTP. Please try again.')
            return redirect(url_for('signup'))

    return render_template('verify_otp.html')


@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    """Verify OTP during login process."""
    if request.method == 'POST':
        entered_otp = request.form['otp']

        # Retrieve and remove OTP from session immediately after reading
        stored_otp = session.pop('otp', None)

        # Check if OTP exists and if it matches the entered OTP
        if stored_otp is not None and int(entered_otp) == stored_otp:
            return redirect(url_for('upload_file'))
        else:
            flash('Invalid or expired OTP. Please try again.')
            return redirect(url_for('login'))


@app.route('/', methods=['GET', 'POST'])
def login():
    """Handle user and admin login with OTP verification."""
    if request.method == 'POST':
        # Check if OTP was submitted
        if 'otp' in session:
            entered_otp = request.form.get('otp')
            if entered_otp == session['otp']:
                # OTP is correct, log in the user
                session.pop('otp', None)
                return redirect(url_for('upload_file'))
            else:
                flash('Invalid OTP. Please try again.')
                return redirect(url_for('login'))

        # Regular login process
        username = request.form['username']
        password = request.form['password']

        # Admin login check
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin'] = True
            return redirect(url_for('admin_dashboard'))

        # Check if user exists and password is correct
        if username in users_db and users_db[username]['password'] == password:
            # Send OTP to user's email
            recipient_email = users_db[username]['email']
            otp = send_otp_email(recipient_email, SMTP_SERVER, SMTP_PORT, SMTP_EMAIL, SMTP_PASSWORD)
            print(f"otp: {otp}")
            if otp is not None:
                session['otp'] = otp
                session['username'] = username
                return render_template('login.html', otp_required=True)
            else:
                flash('Failed to send OTP. Please try again.')
                return redirect(url_for('login'))
        else:
            flash('Incorrect username or password, please try again.')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    """Admin dashboard to view and delete users."""
    if 'admin' not in session or not session['admin']:
        flash("Unauthorized access.")
        return redirect(url_for('login'))

    if request.method == 'POST':
        username_to_delete = request.form['username_to_delete']
        if username_to_delete in users_db:
            del users_db[username_to_delete]
            save_users(users_db)
            flash(f"User '{username_to_delete}' has been deleted.")
        else:
            flash("User not found. Please try again.")
        return redirect(url_for('admin_dashboard'))

    return render_template('admin_dashboard.html', users=users_db)


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """Handle file upload and start encryption process."""
    if request.method == 'POST':
        uploaded_file = request.files['file']
        if uploaded_file.filename != '':
            # Ensure the 'uploads' folder exists
            os.makedirs('uploads', exist_ok=True)
            uploaded_file_path = os.path.join('uploads', uploaded_file.filename)
            uploaded_file.save(uploaded_file_path)

            # Generate unique session ID for progress tracking
            session_id = f"enc_{int(time.time() * 1000)}_{random.randint(1000, 9999)}"
            progress_data[session_id] = {'percentage': 0, 'stage': 'starting', 'status': 'processing'}

            # Start background processing
            thread = threading.Thread(
                target=process_encryption, 
                args=(uploaded_file_path, uploaded_file.filename, session_id, progress_data)
            )
            thread.daemon = True
            thread.start()

            # Return immediately with session_id
            return jsonify({
                "message": "Processing started",
                "session_id": session_id,
                "status": "processing"
            })

    return render_template('upload.html')


@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    """Serve uploaded files."""
    return send_from_directory('uploads', filename)


@app.route('/decrypt_file', methods=['POST'])
def decrypt_file():
    """Handle file decryption request."""
    # Get the uploaded file
    pgn_file = request.files['pgn_file']
    
    # Save it temporarily
    os.makedirs('uploads', exist_ok=True)
    temp_pgn_path = os.path.join('uploads', f"temp_{int(time.time())}_{pgn_file.filename}")
    pgn_file.save(temp_pgn_path)

    # Generate unique session ID
    session_id = f"dec_{int(time.time() * 1000)}_{random.randint(1000, 9999)}"
    progress_data[session_id] = {'percentage': 0, 'stage': 'starting', 'status': 'processing'}

    # Start background processing
    thread = threading.Thread(
        target=process_decryption,
        args=(temp_pgn_path, pgn_file.filename, session_id, progress_data)
    )
    thread.daemon = True
    thread.start()

    # Return immediately
    return jsonify({
        "message": "Decryption started",
        "session_id": session_id,
        "status": "processing"
    })


@app.route('/delete_account', methods=['GET', 'POST'])
def delete_account():
    """Allow users to delete their own accounts."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match. Please try again.')
            return redirect(url_for('delete_account'))

        if username in users_db and users_db[username]['password'] == password:
            del users_db[username]
            save_users(users_db)
            flash('Account deleted successfully.')
            return redirect(url_for('signup'))
        else:
            flash('Incorrect password or username. Please try again.')
            return redirect(url_for('delete_account'))

    return render_template('delete_account.html')


@app.route('/admin/delete_user/<username>', methods=['POST'])
def delete_user(username):
    """Admin route to delete a user directly from the dashboard."""
    if 'admin' in session and session['admin']:
        if username in users_db:
            del users_db[username]
            save_users(users_db)
            flash(f'User {username} deleted successfully.')
    return redirect(url_for('admin_dashboard'))


@app.route('/logout')
def logout():
    """Clear session and logout user."""
    session.clear()
    return redirect(url_for('login'))


@app.route('/progress/<session_id>')
def get_progress(session_id):
    """Endpoint to get the current progress of encryption/decryption."""
    if session_id in progress_data:
        return jsonify(progress_data[session_id])
    return jsonify({'percentage': 0, 'stage': 'waiting'})


if __name__ == '__main__':
    os.makedirs('uploads', exist_ok=True)
    app.run(debug=True)