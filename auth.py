from flask import session, flash, redirect, url_for
from functools import wraps
from config import Config

def check_admin():
    return 'admin' in session and session['admin']

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not check_admin():
            flash("Unauthorized access.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def verify_admin_credentials(username, password):
    return username == Config.ADMIN_USERNAME and password == Config.ADMIN_PASSWORD