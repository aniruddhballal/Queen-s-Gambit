from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session
import os, base64, json, time
from flask import jsonify
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from checkmate import make_gambit
from unmate import undo_gambit
from pgn_aes192_rsa4096 import aes_encrypt, aes_decrypt, rsa_encrypt, rsa_decrypt  # Import from the new module

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

# Helper function to XOR two hex strings and return the result
def xor_hex_strings(hex1, hex2):
    """Helper function to XOR two hex strings and return the result."""
    max_length = max(len(hex1), len(hex2))
    hex1 = hex1.zfill(max_length)  # Zero-pad to ensure equal length
    hex2 = hex2.zfill(max_length)  # Zero-pad to ensure equal length
    return ''.join(format(int(a, 16) ^ int(b, 16), 'x') for a, b in zip(hex1, hex2))

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        uploaded_file = request.files['file']
        if uploaded_file.filename != '':
            # Ensure the 'uploads' folder exists
            os.makedirs('uploads', exist_ok=True)
            base_filename = os.path.splitext(uploaded_file.filename)[0]
            uploaded_file_path = os.path.join('uploads', uploaded_file.filename)
            uploaded_file.save(uploaded_file_path)

            # Call the encode function to get PGN (assumed to be a string)
            encoded_pgn = make_gambit(uploaded_file_path)

            print("Generating AES key...")
            # Generate AES key
            aes_key = get_random_bytes(32)  # AES-256 key is 32 bytes
            print("AES key generated.")

            # Generate RSA keys
            print("Generating RSA key...")
            tgen1 = time.time()
            rsa_key = RSA.generate(4096)
            public_key = rsa_key.publickey()
            tgen2 = time.time()
            print(f"RSA key generated in {tgen2-tgen1:.2f} seconds.")

            # Save the RSA-encrypted AES key in a file
            keys_filename = get_random_bytes(24)
            keys_filename_hex = keys_filename.hex()  # Random key for filename
            keys_xor_result = bytes(b ^ 0xff for b in keys_filename)
            keys_xor_hex_str = keys_xor_result.hex()

            # Ensure the 'rsa_keys' folder exists
            rsa_keys_directory = 'rsa_keys'
            os.makedirs(rsa_keys_directory, exist_ok=True)

            # Generate public and private key filenames based on XOR logic
            def xor_with_hex_string(original_hex, target_hex):
                return ''.join(format(int(a, 16) ^ int(b, 16), 'x') for a, b in zip(original_hex, target_hex))

            # Target hex values for XOR: all 7's and all 8's (24 characters, hex)
            all_sevens = '1' * len(keys_filename_hex)  # Target for public key XOR result
            all_eights = 'a' * len(keys_filename_hex)  # Target for private key XOR result

            # XOR to get the public and private key filenames
            public_key_filename_hex = xor_with_hex_string(keys_filename_hex, all_sevens)
            private_key_filename_hex = xor_with_hex_string(keys_filename_hex, all_eights)

            # Save the RSA keys in the 'rsa_keys' folder with the new filenames
            rsa_keys_directory = 'rsa_keys'
            os.makedirs(rsa_keys_directory, exist_ok=True)

            # Save the RSA private key in the rsa_keys folder
            private_key_path = os.path.join(rsa_keys_directory, f'{private_key_filename_hex}.pem')
            with open(private_key_path, 'wb') as f:
                f.write(rsa_key.export_key())  # Save private key

            # Save the RSA public key in the rsa_keys folder
            public_key_path = os.path.join(rsa_keys_directory, f'{public_key_filename_hex}.pem')
            with open(public_key_path, 'wb') as f:
                f.write(public_key.export_key())  # Save public key

            # Encrypt AES key with RSA public key
            rsa_encrypted_aes_key = rsa_encrypt(aes_key, public_key)

            # Ensure the 'keys' folder exists
            keys_directory = "keys"
            os.makedirs(keys_directory, exist_ok=True)
            keys_filename_string = os.path.join(keys_directory, f"{keys_filename_hex}.txt")
            
            with open(keys_filename_string, "w") as file:
                file.write(base64.b64encode(rsa_encrypted_aes_key).decode('utf-8'))

            # Encrypt the PGN data with AES
            aes_encrypted_pgn = aes_encrypt(encoded_pgn.encode('utf-8'), aes_key)

            # Save the encrypted data as a .pgn file
            pgn_file_name = f"{keys_xor_hex_str}.pgn"
            pgn_file_path = os.path.join('uploads', pgn_file_name)
            with open(pgn_file_path, "wb") as f:
                f.write(aes_encrypted_pgn)

            return jsonify({"message": "File converted successfully!", "pgn_file": pgn_file_name})

    return render_template('upload.html')

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory('uploads', filename)

@app.route('/decrypt_file', methods=['POST'])
def decrypt_file():
    # Step 1: Retrieve the uploaded PGN file and the output file name
    pgn_file = request.files['pgn_file']
    pgn_filename = os.path.splitext(pgn_file.filename)[0]
    output_file_name = request.form['output_file']
    
    # Step 2: Check the keys folder for a matching key file using XOR logic
    keys_folder = 'keys'
    matching_key_file = None

    for key_file in os.listdir(keys_folder):
        key_filename = os.path.splitext(key_file)[0]
        xor_result = xor_hex_strings(pgn_filename, key_filename)
        print(f"Checking key file: {key_filename}, XOR result: {xor_result}")  # Debugging output
        if xor_result == 'ffffffffffffffffffffffffffffffffffffffffffffffff':  # 24 f's
            matching_key_file = os.path.join(keys_folder, key_file)
            break

    if not matching_key_file:
        return jsonify({"error": f"No matching key found for {pgn_filename}"}), 400

    # Step 3: Load the RSA-encrypted AES key from the matching key file
    with open(matching_key_file, "r") as file:
        rsa_encrypted_aes_key_base64 = file.read().strip()  # Ensure it’s base64 encoded
        rsa_encrypted_aes_key = base64.b64decode(rsa_encrypted_aes_key_base64)

    os.remove(matching_key_file)

    # Step 4: Find the corresponding private key and public key
    rsa_keys_directory = 'rsa_keys'
    private_key = None
    public_key = None
    all_sevens = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'  # Expected XOR result for public key (24-byte hex string, hence 48 chars)
    all_eights = '555555555555555555555555555555555555555555555555'  # Expected XOR result for private key

    for rsa_key_file in os.listdir(rsa_keys_directory):
        rsa_key_filename = os.path.splitext(rsa_key_file)[0]
        xor_with_pgn = xor_hex_strings(pgn_filename, rsa_key_filename)
        print(xor_with_pgn)

        if xor_with_pgn == all_sevens:
            public_key_path = os.path.join(rsa_keys_directory, rsa_key_file)
            with open(public_key_path, 'rb') as pub_key_file:
                public_key = RSA.import_key(pub_key_file.read())
            print(f"Found public key: {public_key_path}")
        elif xor_with_pgn == all_eights:
            private_key_path = os.path.join(rsa_keys_directory, rsa_key_file)
            with open(private_key_path, 'rb') as priv_key_file:
                private_key = RSA.import_key(priv_key_file.read())
                if private_key.has_private():  # Double check it's a private key
                    print(f"Found private key: {private_key_path}")
                else:
                    print(f"Error: {private_key_path} is not a private key!")

    # Check if both public and private keys are found
    if not private_key or not public_key:
        return jsonify({"error": "Matching RSA key files not found."}), 400

    os.remove(private_key_path)
    os.remove(public_key_path)

    # Step 5: Decrypt the AES key using the private RSA key
    try:
        aes_key = rsa_decrypt(rsa_encrypted_aes_key, private_key)
    except Exception as e:
        return jsonify({"error": f"Failed to decrypt AES key: {str(e)}"}), 500

    # Step 6: Decrypt the PGN file using the decrypted AES key
    encrypted_pgn_data = pgn_file.read()  # Read as binary since it's encrypted
    try:
        decrypted_pgn_string = aes_decrypt(encrypted_pgn_data, aes_key).decode('utf-8')  # Ensure utf-8 decoding
    except Exception as e:
        return jsonify({"error": f"Failed to decrypt the PGN file: {str(e)}"}), 500

    # Step 7: Save the decrypted data to the specified output file
    output_file_path = f'uploads/{output_file_name}'
    undo_gambit(decrypted_pgn_string, output_file_path)  # Assuming decode() converts PGN back to original format

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