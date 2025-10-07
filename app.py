from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session
import os
from flask import jsonify
import json
from encode import encode
from decode import decode
from pgndouble import aes_encrypt, aes_decrypt, des_encrypt, des_decrypt
from Crypto.Random import get_random_bytes

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

            # Call the encode function to get PGN (assumed to be a string)
            encoded_pgn = encode(uploaded_file_path)

            # Define keys for AES and DES (must be 16 bytes for AES, 8 bytes for DES)
            aes_key = get_random_bytes(16)
            des_key = get_random_bytes(8)

            # Save keys to a file (as hex values)
            aes_key_hex = aes_key.hex()
            des_key_hex = des_key.hex()
            with open("keys.txt", "w") as file:
                file.write(f"AES Key: {aes_key_hex}\n")
                file.write(f"DES Key: {des_key_hex}\n")

            # Encrypt the encoded PGN (convert string to bytes before encrypting)
            aes_encrypted_pgn = aes_encrypt(encoded_pgn.encode('utf-8'), aes_key)
            des_encrypted_pgn = des_encrypt(aes_encrypted_pgn, des_key)

            # Save the doubly encrypted data as bytes to the .pgn file
            pgn_file_name = f'{base_filename}.pgn'
            pgn_file_path = os.path.join('uploads', pgn_file_name)
            with open(pgn_file_path, "wb") as f:  # Write as binary
                f.write(des_encrypted_pgn)

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

    # Read the doubly encrypted file in binary mode
    double_encrypted_pgn = pgn_file.read()  # Read as bytes

    # Read the saved keys from the keys.txt file
    with open("keys.txt", "r") as file:
        lines = file.readlines()

    # Step 2: Extracting and converting the keys back to bytes
    aes_key_hex = lines[0].strip().split(": ")[1]  # Extracting the AES key
    des_key_hex = lines[1].strip().split(": ")[1]  # Extracting the DES key
    os.remove("keys.txt")

    # Step 3: Converting from hex back to bytes
    aes_key = bytes.fromhex(aes_key_hex)
    des_key = bytes.fromhex(des_key_hex)

    # Decrypt the file (first DES, then AES)
    des_decrypted_pgn = des_decrypt(double_encrypted_pgn, des_key)
    aes_decrypted_pgn = aes_decrypt(des_decrypted_pgn, aes_key)

    # Step 4: Convert the decrypted bytes back to a string
    decrypted_pgn_string = aes_decrypted_pgn.decode('utf-8')

    # Now call your decode function with the decrypted data
    output_file_path = f'uploads/{output_file_name}'  # Ensure this path is correct
    decode(decrypted_pgn_string, output_file_path)  # Call your decode function

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