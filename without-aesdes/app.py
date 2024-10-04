from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session
import os
from flask import jsonify
import json
from encode import encode
from decode import decode

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Load users from JSON file
def load_users():
    try:
        with open('users.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

# Save users to JSON file
def save_users():
    with open('users.json', 'w') as f:
        json.dump(users_db, f)

users_db = load_users()

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users_db and users_db[username] == password:
            return redirect(url_for('upload_file'))
        else:
            flash('Incorrect username or password, please try again.')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users_db:
            flash('Username already exists. Please choose a different one.')
            return redirect(url_for('signup'))
        else:
            users_db[username] = password
            save_users()  # Save the updated users_db
            flash('Account created successfully! Please log in.')
            return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        uploaded_file = request.files['file']
        if uploaded_file.filename != '':
            # Get the original filename without extension and add .pgn
            base_filename = os.path.splitext(uploaded_file.filename)[0]
            uploaded_file_path = os.path.join('uploads', uploaded_file.filename)
            uploaded_file.save(uploaded_file_path)

            # Call the encode function to get PGN
            encoded_pgn = encode(uploaded_file_path)

            # Save the PGN file with the same name as the uploaded file
            pgn_file_name = f'{base_filename}.pgn'
            pgn_file_path = os.path.join('uploads', pgn_file_name)
            with open(pgn_file_path, "w") as f:
                f.write(encoded_pgn)

            # Return a JSON response with the correct PGN filename
            return jsonify({"message": "File converted successfully!", "pgn_file": pgn_file_name})

    return render_template('upload.html')

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory('uploads', filename)

@app.route('/decrypt_file', methods=['POST'])
def decrypt_file():
    pgn_file = request.files['pgn_file']
    output_file_name = request.form['output_file']

    # Process the PGN file and save the output
    output_file_path = f'uploads/{output_file_name}'  # Ensure this path is correct
    pgn_string = pgn_file.read().decode('utf-8')  # Read the PGN file
    decode(pgn_string, output_file_path)  # Call your decode function

    return jsonify({"message": "File decrypted successfully!", "output_file": output_file_name})

@app.route('/delete_account', methods=['GET', 'POST'])
def delete_account():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match. Please try again.')
            return redirect(url_for('delete_account'))

        if username in users_db and users_db[username] == password:
            del users_db[username]
            save_users()  # Save the updated users_db
            flash('Account deleted successfully.')
            return redirect(url_for('signup'))
        else:
            flash('Incorrect password or username. Please try again.')
            return redirect(url_for('delete_account'))

    return render_template('delete_account.html')

@app.route('/logout')
def logout():
    session.clear()  # Clear the session data
    return redirect(url_for('login'))  # Redirect to the login page

if __name__ == '__main__':
    os.makedirs('uploads', exist_ok=True)  # Ensure the uploads directory exists
    app.run(debug=True)