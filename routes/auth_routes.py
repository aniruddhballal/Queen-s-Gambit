from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from database import UserDatabase
from email_service import EmailService
from auth import verify_admin_credentials

auth_bp = Blueprint('auth', __name__)
user_db = UserDatabase()
email_service = EmailService()

@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        if user_db.user_exists(username):
            flash('Username already taken. Please choose another.')
            return redirect(url_for('auth.signup'))

        otp = email_service.send_otp_email(email)
        if otp is not None:
            session['otp'] = otp
            session['temp_user'] = {'username': username, 'password': password, 'email': email}
            return redirect(url_for('auth.verify_signup_otp'))
        else:
            flash('Failed to send OTP. Please try again.')
            return redirect(url_for('auth.signup'))

    return render_template('signup.html')

@auth_bp.route('/verify_signup_otp', methods=['GET', 'POST'])
def verify_signup_otp():
    if request.method == 'POST':
        entered_otp = request.form['otp']
        stored_otp = session.pop('otp', None)
        
        if stored_otp is not None and int(entered_otp) == stored_otp:
            temp_user = session.pop('temp_user', None)
            if temp_user:
                user_db.add_user(temp_user['username'], temp_user['password'], temp_user['email'])
                flash('Signup successful! Please log in.')
                return redirect(url_for('auth.login'))
            else:
                flash('Session expired. Please try signing up again.')
                return redirect(url_for('auth.signup'))
        else:
            flash('Invalid OTP. Please try again.')
            return redirect(url_for('auth.signup'))

    return render_template('verify_otp.html')

@auth_bp.route('/verify_otp', methods=['POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form['otp']
        stored_otp = session.pop('otp', None)

        if stored_otp is not None and int(entered_otp) == stored_otp:
            return redirect(url_for('file.upload_file'))
        else:
            flash('Invalid or expired OTP. Please try again.')
            return redirect(url_for('auth.login'))

@auth_bp.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if 'otp' in session:
            entered_otp = request.form.get('otp')
            if entered_otp == session['otp']:
                session.pop('otp', None)
                return redirect(url_for('file.upload_file'))
            else:
                flash('Invalid OTP. Please try again.')
                return redirect(url_for('auth.login'))

        username = request.form['username']
        password = request.form['password']

        if verify_admin_credentials(username, password):
            session['admin'] = True
            return redirect(url_for('admin.admin_dashboard'))

        if user_db.verify_credentials(username, password):
            user = user_db.get_user(username)
            recipient_email = user['email']
            otp = email_service.send_otp_email(recipient_email)
            print(f"otp: {otp}")
            if otp is not None:
                session['otp'] = otp
                session['username'] = username
                return render_template('login.html', otp_required=True)
            else:
                flash('Failed to send OTP. Please try again.')
                return redirect(url_for('auth.login'))
        else:
            flash('Incorrect username or password, please try again.')
            return redirect(url_for('auth.login'))

    return render_template('login.html')

@auth_bp.route('/delete_account', methods=['GET', 'POST'])
def delete_account():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match. Please try again.')
            return redirect(url_for('auth.delete_account'))

        if user_db.verify_credentials(username, password):
            user_db.delete_user(username)
            flash('Account deleted successfully.')
            return redirect(url_for('auth.signup'))
        else:
            flash('Incorrect password or username. Please try again.')
            return redirect(url_for('auth.delete_account'))

    return render_template('delete_account.html')

@auth_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))