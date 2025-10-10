from flask import Blueprint, render_template, request, redirect, url_for, flash
from database import UserDatabase
from auth import admin_required

admin_bp = Blueprint('admin', __name__)
user_db = UserDatabase()

@admin_bp.route('/admin_dashboard', methods=['GET', 'POST'])
@admin_required
def admin_dashboard():
    if request.method == 'POST':
        username_to_delete = request.form['username_to_delete']
        if user_db.delete_user(username_to_delete):
            flash(f"User '{username_to_delete}' has been deleted.")
        else:
            flash("User not found. Please try again.")
        return redirect(url_for('admin.admin_dashboard'))

    return render_template('admin_dashboard.html', users=user_db.get_all_users())

@admin_bp.route('/admin/delete_user/<username>', methods=['POST'])
@admin_required
def delete_user(username):
    if user_db.delete_user(username):
        flash(f'User {username} deleted successfully.')
    return redirect(url_for('admin.admin_dashboard'))