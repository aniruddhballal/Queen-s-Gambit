from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session
import os
from flask import jsonify
import json
from encode import encode
from decode import decode
from pgndouble import aes_encrypt, aes_decrypt, des_encrypt, des_decrypt
from Crypto.Random import get_random_bytes

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generates a random 24-byte key

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

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory('uploads', filename)

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
            keys_filename = get_random_bytes(24)
            keys_xor_result = bytes(b ^ 0xff for b in keys_filename)

            # Save keys to a file (as hex values)
            aes_key_hex = aes_key.hex()
            des_key_hex = des_key.hex()
            keys_filename_hex = keys_filename.hex()
            keys_xor_hex_str = keys_xor_result.hex()
            # Directory name where the keys will be saved
            keys_directory = "keys"

            # Create the directory if it doesn't exist
            os.makedirs(keys_directory, exist_ok=True)

            keys_filename_string = os.path.join(keys_directory, f"{keys_filename_hex}.txt")
            with open(keys_filename_string, "w") as file:
                file.write(f"{aes_key_hex}\n")
                file.write(f"{des_key_hex}\n")

            # Encrypt the encoded PGN (convert string to bytes before encrypting)
            aes_encrypted_pgn = aes_encrypt(encoded_pgn.encode('utf-8'), aes_key)
            des_encrypted_pgn = des_encrypt(aes_encrypted_pgn, des_key)

            # Save the doubly encrypted data as bytes to the .pgn file
            pgn_file_name = f"{keys_xor_hex_str}.pgn"
            pgn_file_path = os.path.join('uploads', pgn_file_name)
            with open(pgn_file_path, "wb") as f:  # Write as binary
                f.write(des_encrypted_pgn)

            # Return a JSON response with the correct PGN filename
            return jsonify({"message": "File converted successfully!", "pgn_file": pgn_file_name})

    return render_template('upload.html')

def xor_hex_strings(hex1, hex2):
    """Helper function to XOR two hex strings and return the result."""
    max_length = max(len(hex1), len(hex2))
    hex1 = hex1.zfill(max_length)  # Zero-pad to ensure equal length
    hex2 = hex2.zfill(max_length)  # Zero-pad to ensure equal length
    return ''.join(format(int(a, 16) ^ int(b, 16), 'x') for a, b in zip(hex1, hex2))


@app.route('/decrypt_file', methods=['POST'])
def decrypt_file():
    # Step 1: Retrieve the uploaded PGN file and its filename
    pgn_file = request.files['pgn_file']
    pgn_filename = os.path.splitext(pgn_file.filename)[0]  # Get filename without extension
    output_file_name = request.form['output_file']
    
    # Step 2: Check the keys folder for a matching key file using XOR
    keys_folder = 'keys'
    matching_key_file = None

    # Iterate through all files in the keys folder
    for key_file in os.listdir(keys_folder):
        key_file_path = os.path.join(keys_folder, key_file)
        key_filename = os.path.splitext(key_file)[0]  # Get key filename without extension
        #print(key_filename)
        #print(pgn_filename)

        # XOR the uploaded PGN filename and the key filename
        xor_result = xor_hex_strings(pgn_filename, key_filename)
        #print(xor_result)

        # If the XOR result is 24 f's, it's the correct key file
        if xor_result == 'ffffffffffffffffffffffffffffffffffffffffffffffff':  # 24 f's as each XOR should result in 'ff'
            matching_key_file = key_file_path
            #print("here2")
            break

    if not matching_key_file:
        return jsonify({
            "error": f"No matching key found for the uploaded file {pgn_filename}",
            "pgn_filename": pgn_filename,
            "keys_folder": os.listdir(keys_folder)  # List all key files
        }), 400


    # Step 3: Read the matched key file
    with open(matching_key_file, "r") as file:
        lines = file.readlines()

    aes_key_hex = lines[0].strip()  # Extract the AES key from the first line
    des_key_hex = lines[1].strip()  # Extract the DES key from the second line

    # Delete the key file after reading
    os.remove(matching_key_file)

    # Step 4: Convert the hex keys back to bytes
    aes_key = bytes.fromhex(aes_key_hex)
    des_key = bytes.fromhex(des_key_hex)

    # Step 5: Decrypt the PGN file (first DES, then AES)
    double_encrypted_pgn = pgn_file.read()  # Read the uploaded file's content as bytes
    des_decrypted_pgn = des_decrypt(double_encrypted_pgn, des_key)  # DES decryption
    aes_decrypted_pgn = aes_decrypt(des_decrypted_pgn, aes_key)  # AES decryption

    # Step 6: Convert the decrypted bytes back to a string (assuming it's a UTF-8 encoded string)
    decrypted_pgn_string = aes_decrypted_pgn.decode('utf-8')

    # Step 7: Save the decrypted data to the specified output file
    output_file_path = f'uploads/{output_file_name}'
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