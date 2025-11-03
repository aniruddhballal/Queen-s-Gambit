from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session
import os, base64, json, time, smtplib, random, base64, threading
from flask import jsonify
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from email.mime.text import MIMEText
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from math import log2
from chess import pgn, Board
from io import StringIO
from dotenv import load_dotenv

app = Flask(__name__)

# Add this global variable after the app initialization
progress_data = {}  # Dictionary to store progress for each session

# load .env into os.environ (call once at app start)
load_dotenv()

app.secret_key = os.getenv('SECRET_KEY', os.urandom(24))  # Generates a random 24-byte key

# Admin login credentials

# read values (no default -> None if missing)
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT"))
SMTP_EMAIL = os.getenv("SMTP_EMAIL")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

# Load users from JSON file
def load_users():
    try:
        with open('users.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

# Save users to JSON file
def save_users(users_db):
    with open('users.json', 'w') as f:
        json.dump(users_db, f)

users_db = load_users()

# Function to send OTP email
def send_otp_email(recipient_email):
    otp = random.randint(100000, 999999)
    subject = "Your OTP Code"
    body = f"Your OTP code is: {otp}"
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SMTP_EMAIL
    msg["To"] = recipient_email

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.sendmail(SMTP_EMAIL, recipient_email, msg.as_string())
        return otp
    except Exception as e:
        print(f"Error sending email: {e}")
        return None
    

def no_to_bin_str(num: int, bits: int):
    # Convert the number to a binary string and remove the '0b' prefix
    binary = bin(num)[2:]

    # Pad the binary string with leading zeros to ensure it's 'bits' long
    return binary.zfill(bits)

def random_user_id():
    return f"{random.randint(100000, 999999)}"

def random_metadata():
    events = [
        "Friendly Match", "Tournament", "Casual Game", "Championship", 
        "Club Championship", "Simultaneous Exhibition", "Charity Match", 
        "Blitz Tournament", "Rapid Championship", "Online Invitational"
    ]
    locations = [
        "Local Club", "Online", "City Park", "University Hall", "Community Center", 
        "Chess Cafe", "Mountain Retreat", "Coastal Town", "National Stadium", 
        "Historical Landmark"
    ]
    expected_openings = [
        "Sicilian Defense", "French Defense", "Caro-Kann", "Ruy Lopez", "Italian Game", 
        "English Opening", "King's Indian Defense", "Queen's Gambit", 
        "Nimzo-Indian Defense", "Pirc Defense", "Grünfeld Defense"
    ]
    
    # Generate the first player's rating
    white_elo = random.randint(200, 3000)
    # Calculate the range for the second player's rating
    lower_bound = int(white_elo * 0.9)
    upper_bound = int(white_elo * 1.1)
    
    # Generate the second player's rating within the specified range
    black_elo = random.randint(lower_bound, upper_bound)
    
    results = ["1-0", "0-1", "1/2-1/2", "*"]  # Possible outcomes

    metadata = {
        "Event": random.choice(events),
        "Site": random.choice(locations),
        "Date": f"{random.randint(1990, 2023)}.{random.randint(1, 12):02d}.{random.randint(1, 31):02d}",
        "Round": str(random.randint(1, 15)),
        "White": random_user_id(),  # Random user ID for White player
        "Black": random_user_id(),  # Random user ID for Black player
        "ExpectedOpening": random.choice(expected_openings),
        "WhiteElo": str(white_elo),
        "BlackElo": str(black_elo),
        "Result": random.choice(results),
        "Annotator": random_user_id(),  # Random ID for annotator
        "Variation": random.choice(["Main Line", "Alternative Line", "Quiet Move", "Aggressive Line", "Theoretical Novelty"]),
        "EventDate": f"{random.randint(1990, 2023)}.{random.randint(1, 12):02d}.{random.randint(1, 31):02d}",
        "TimeControl": random.choice(["3+2", "5+0", "10+0", "15+10", "30+0", "60+0", "90+30"])
    }

    # Randomly select a number of keys to hide
    keys_to_hide = random.sample(list(metadata.keys()), random.randint(1, len(metadata) // 2))
    
    # Set the selected keys' values to "Hidden"
    for key in keys_to_hide:
        metadata[key] = "Hidden"

    # return ""

    return metadata

def make_gambit(sample_file: str, session_id: str = None):
    print("Making the Gambit...")
    bittify = (255).bit_length()

    with open(sample_file, "rb") as f:
        file01 = list(f.read())

    bits = bittify * len(file01)  # Total bits to process
    start_time = time.time()  # Add this line
    pgnlist = []
    current_pos = 0
    board_instance = Board()

    while True:
        # Update progress
        if session_id:
            progress_percentage = min(100, (current_pos / bits) * 100)
            elapsed_time = time.time() - start_time
            speed = current_pos / elapsed_time if elapsed_time > 0 else 0
            progress_data[session_id] = {
                'current': current_pos,
                'total': bits,
                'percentage': round(progress_percentage, 2),
                'stage': 'encoding',
                'speed': round(speed, 2),
                'elapsed_time': round(elapsed_time, 2)
            }
        
        gen_moves = board_instance.generate_legal_moves()
        moves_list = list(board_instance.generate_legal_moves())
        log_length = int(log2(len(moves_list)))
        remaining_bits = bits - current_pos
        bits_req = min(log_length, remaining_bits)

        bits_map_set_of_moves = {}
        valid_moves = {
            anti_illegal_move.uci(): no_to_bin_str(i, bits_req)
            for i, anti_illegal_move in enumerate(gen_moves)
            if len(no_to_bin_str(i, bits_req)) <= bits_req
        }

        bits_map_set_of_moves.update(valid_moves)
        next_byte_i = current_pos // bittify
        strs = ''

        for byte1 in file01[next_byte_i:next_byte_i + 2]:
            binary_string = no_to_bin_str(byte1, bittify)
            strs += binary_string

        start_index = current_pos % bittify
        next_str = ''

        for i in range(bits_req):
            if start_index + i < len(strs):
                next_str += strs[start_index + i]

        current_pos += bits_req

        for movei in bits_map_set_of_moves:
            bits_mapped = bits_map_set_of_moves[movei]
            if bits_mapped == next_str:
                board_instance.push_uci(movei)
                break
        
        if (board_instance.legal_moves.count() <= 1.5 or current_pos >= bits):
            pgn_ = pgn.Game()
            metadata = random_metadata()

            for key, value in metadata.items():
               pgn_.headers[key] = value
            
            pgn_.add_line(board_instance.move_stack)
            pgnlist.append(str(pgn_))
            board_instance.reset()

        if current_pos >= bits:
            break

    # Set progress to 100% when done
    if session_id:
        elapsed_time = time.time() - start_time
        avg_speed = bits / elapsed_time if elapsed_time > 0 else 0
        progress_data[session_id] = {
            'current': bits,
            'total': bits,
            'percentage': 100.0,
            'stage': 'encoding',
            'speed': round(avg_speed, 2),
            'elapsed_time': round(elapsed_time, 2)
        }
    
    print("Gambit done.")
    return "\n\n".join(pgnlist)

def listify_pgns(pgn_string: str):  
    # Initialize an empty list to store parsed pgn.Game objects
    games = []
    
    # Create an in-memory file-like object from the PGN string
    pgn_stream = StringIO(pgn_string)

    # Read the first chess game from the PGN string
    game = pgn.read_game(pgn_stream)
    
    # Loop through the PGN stream and read each game until no more games are left
    while game:  # While there is a valid game (not None)
        games.append(game)  # Add the current game to the list
        game = pgn.read_game(pgn_stream)  # Read the next game from the stream
    
    # Return the list of all parsed games
    return games

def undo_gambit(games_pgn: str, output_og_sample_file: str, session_id: str = None):
    print("Undoing the Gambit...")
    moves_processed = 0
    bittify = (255).bit_length()
    
    pgn_list = listify_pgns(games_pgn)
    iterable_games = list(pgn_list)
    total_games = len(iterable_games)
    start_time = time.time()  # Add this line

    op_dec_file = open(output_og_sample_file, "wb")
    try:
        dec_data = ""
        for pgn_g_num, g in enumerate(iterable_games):
            # Update progress
            if session_id:
                progress_percentage = ((pgn_g_num + 1) / total_games) * 100
                elapsed_time = time.time() - start_time
                games_per_sec = (pgn_g_num + 1) / elapsed_time if elapsed_time > 0 else 0
                progress_data[session_id] = {
                    'current': pgn_g_num + 1,
                    'total': total_games,
                    'percentage': round(progress_percentage, 2),
                    'stage': 'decoding',
                    'speed': round(games_per_sec, 2),
                    'elapsed_time': round(elapsed_time, 2)
                }

            board_instance = Board()
            moves_list = list(g.mainline_moves())
            moves_processed += len(moves_list)

            for move_i, iterable_moves in enumerate(moves_list):
                moves_possible = board_instance.generate_legal_moves()
                strs = [move_iterable.uci() for move_iterable in moves_possible]

                indexify_move = strs.index(iterable_moves.uci())
                pad_indexed_bin = bin(indexify_move)[2:]

                game_over = (pgn_g_num == len(iterable_games) - 1)
                last_move = (move_i == len(moves_list) - 1)

                if game_over and last_move:
                    moves_count = len(strs)
                    log_length = int(log2(moves_count))
                    remaining_bits = bittify - (len(dec_data) % bittify)
                    bits_req = min(log_length, remaining_bits)
                else:
                    moves_count = len(strs)
                    bits_req = int(log2(moves_count))

                test_pad = bits_req - len(pad_indexed_bin)
                non_neg_padding = max(0, test_pad)
                padding = "0" * non_neg_padding
                pad_indexed_bin = padding + pad_indexed_bin

                next_move = iterable_moves.uci()
                board_instance.push_uci(next_move)

                dec_data += pad_indexed_bin

                if len(dec_data) % bittify == 0:
                    byte_values = []
                    num_chunks = len(dec_data) / bittify
                    i = 0

                    while i < int(num_chunks):
                        start_index = i * bittify
                        end_index = start_index + bittify

                        chunk = ''
                        for indexify_move in range(start_index, end_index):
                            chunk += dec_data[indexify_move]

                        byte_value = 0
                        for bit in chunk:
                            byte_value = byte_value * 2 + int(bit)

                        byte_values.append(byte_value)
                        i += 1

                    for byte_value in byte_values:
                        byte = byte_value.to_bytes(1, byteorder='big')
                        op_dec_file.write(byte)

                    dec_data = ""
    finally:
        op_dec_file.close()
        # Set progress to 100% when done
        if session_id:
            elapsed_time = time.time() - start_time
            avg_speed = total_games / elapsed_time if elapsed_time > 0 else 0
            progress_data[session_id] = {
                'current': total_games,
                'total': total_games,
                'percentage': 100.0,
                'stage': 'decoding',
                'speed': round(avg_speed, 2),
                'elapsed_time': round(elapsed_time, 2)
            }
    print("Gambit undone.")

# Function to encrypt data with AES-256
def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = cipher.iv
    return base64.b64encode(iv + ct_bytes)

# Function to decrypt AES-256 encrypted data
def aes_decrypt(enc_data, key):
    enc_data = base64.b64decode(enc_data)
    iv = enc_data[:AES.block_size]
    ct = enc_data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

# Function to encrypt data with RSA-4096 (used for the AES key)
def rsa_encrypt(data, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(data)

# Function to decrypt data with RSA-4096 (used to decrypt the AES key)
def rsa_decrypt(encrypted_data, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(encrypted_data)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        # Check if username already exists
        if username in users_db:
            flash('Username already taken. Please choose another.')
            return redirect(url_for('signup'))

        # Send OTP and store user data temporarily in session
        otp = send_otp_email(email)
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
    if request.method == 'POST':
        entered_otp = request.form['otp']

        # Retrieve and remove OTP from session immediately after reading
        stored_otp = session.pop('otp', None)

        # Check if OTP exists and if it matches the entered OTP
        if stored_otp is not None and int(entered_otp) == stored_otp:
            return redirect(url_for('upload_file'))  # Redirect to upload page
        else:
            flash('Invalid or expired OTP. Please try again.')
            return redirect(url_for('login'))  # Redirect back to login

# Login route handling both regular and OTP-based login
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Check if OTP was submitted
        if 'otp' in session:
            entered_otp = request.form.get('otp')
            if entered_otp == session['otp']:
                # OTP is correct, log in the user
                session.pop('otp', None)
                return redirect(url_for('upload_file'))  # Redirect to upload page
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
            otp = send_otp_email(recipient_email)
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

# Admin dashboard to view and delete users
@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
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
            uploaded_file_path = os.path.join('uploads', uploaded_file.filename)
            uploaded_file.save(uploaded_file_path)

            # Generate unique session ID for progress tracking
            session_id = f"enc_{int(time.time() * 1000)}_{random.randint(1000, 9999)}"
            progress_data[session_id] = {'percentage': 0, 'stage': 'starting', 'status': 'processing'}

            # Start background processing
            thread = threading.Thread(
                target=process_encryption, 
                args=(uploaded_file_path, uploaded_file.filename, session_id)
            )
            thread.daemon = True  # Thread will die when main thread dies
            thread.start()

            # Return immediately with session_id
            return jsonify({
                "message": "Processing started",
                "session_id": session_id,
                "status": "processing"
            })

    return render_template('upload.html')

def process_encryption(uploaded_file_path, original_filename, session_id):
    """Background thread function to handle encryption"""
    try:
        # START TIMING
        encryption_start_time = time.time()
        print(f"\n{'='*50}")
        print(f"ENCRYPTION STARTED at {time.strftime('%H:%M:%S')}")
        print(f"{'='*50}")

        # Call the encode function to get PGN
        gambit_start = time.time()
        encoded_pgn = make_gambit(uploaded_file_path, session_id)
        gambit_end = time.time()
        print(f"⏱️  make_gambit() time: {gambit_end - gambit_start:.2f} seconds")

        encoded_pgn = original_filename + '\n' + encoded_pgn

        # Generate AES key
        aes_key = get_random_bytes(32)

        # Generate RSA keys
        print("Generating RSA key...")
        tgen1 = time.time()
        rsa_key = RSA.generate(4096)
        public_key = rsa_key.publickey()
        tgen2 = time.time()
        print(f"⏱️  RSA key generation time: {tgen2-tgen1:.2f} seconds")

        # Save the RSA-encrypted AES key
        keys_filename = get_random_bytes(24)
        keys_filename_hex = keys_filename.hex()
        keys_xor_result = bytes(b ^ 0xff for b in keys_filename)
        keys_xor_hex_str = keys_xor_result.hex()

        # Ensure directories exist
        rsa_keys_directory = 'rsa_keys'
        os.makedirs(rsa_keys_directory, exist_ok=True)

        # Generate key filenames
        all_sevens = '1' * len(keys_filename_hex)
        all_eights = 'a' * len(keys_filename_hex)

        def xor_with_hex_string(original_hex, target_hex):
            return ''.join(format(int(a, 16) ^ int(b, 16), 'x') for a, b in zip(original_hex, target_hex))

        public_key_filename_hex = xor_with_hex_string(keys_filename_hex, all_sevens)
        private_key_filename_hex = xor_with_hex_string(keys_filename_hex, all_eights)

        # Save RSA keys
        private_key_path = os.path.join(rsa_keys_directory, f'{private_key_filename_hex}.pem')
        with open(private_key_path, 'wb') as f:
            f.write(rsa_key.export_key())

        public_key_path = os.path.join(rsa_keys_directory, f'{public_key_filename_hex}.pem')
        with open(public_key_path, 'wb') as f:
            f.write(public_key.export_key())

        # Encrypt AES key with RSA
        rsa_encrypt_start = time.time()
        rsa_encrypted_aes_key = rsa_encrypt(aes_key, public_key)
        rsa_encrypt_end = time.time()
        print(f"⏱️  RSA encryption time: {rsa_encrypt_end - rsa_encrypt_start:.2f} seconds")

        # Save encrypted AES key
        keys_directory = "keys"
        os.makedirs(keys_directory, exist_ok=True)
        keys_filename_string = os.path.join(keys_directory, f"{keys_filename_hex}.txt")
        
        with open(keys_filename_string, "w") as file:
            file.write(base64.b64encode(rsa_encrypted_aes_key).decode('utf-8'))

        # Encrypt the PGN data with AES
        aes_encrypt_start = time.time()
        aes_encrypted_pgn = aes_encrypt(encoded_pgn.encode('utf-8'), aes_key)
        aes_encrypt_end = time.time()
        print(f"⏱️  AES encryption time: {aes_encrypt_end - aes_encrypt_start:.2f} seconds")

        # Save encrypted file
        pgn_file_name = f"{keys_xor_hex_str}.pgn"
        pgn_file_path = os.path.join('uploads', pgn_file_name)
        with open(pgn_file_path, "wb") as f:
            f.write(aes_encrypted_pgn)

        # END TIMING
        encryption_end_time = time.time()
        total_encryption_time = encryption_end_time - encryption_start_time
        
        print(f"\n{'='*50}")
        print(f"✅ ENCRYPTION COMPLETED")
        print(f"⏱️  TOTAL TIME: {total_encryption_time:.2f} seconds")
        print(f"📦 Input file: {original_filename}")
        print(f"📦 Output file: {pgn_file_name}")
        print(f"{'='*50}\n")

        # Update progress data with completion info
        progress_data[session_id] = {
            'percentage': 100.0,
            'stage': 'completed',
            'status': 'completed',
            'pgn_file': pgn_file_name,
            'encryption_time': f"{total_encryption_time:.2f} seconds",
            'message': 'File converted successfully!'
        }

    except Exception as e:
        print(f"❌ ENCRYPTION FAILED: {str(e)}")
        progress_data[session_id] = {
            'percentage': 0,
            'stage': 'failed',
            'status': 'error',
            'error': str(e)
        }

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory('uploads', filename)

@app.route('/decrypt_file', methods=['POST'])
def decrypt_file():
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
        args=(temp_pgn_path, pgn_file.filename, session_id)
    )
    thread.daemon = True
    thread.start()

    # Return immediately
    return jsonify({
        "message": "Decryption started",
        "session_id": session_id,
        "status": "processing"
    })

def process_decryption(temp_pgn_path, original_filename, session_id):
    """Background thread function to handle decryption"""
    try:
        # START TIMING
        decryption_start_time = time.time()
        print(f"\n{'='*50}")
        print(f"DECRYPTION STARTED at {time.strftime('%H:%M:%S')}")
        print(f"{'='*50}")

        pgn_filename = os.path.splitext(original_filename)[0]

        # Find matching key file
        key_search_start = time.time()
        keys_folder = 'keys'
        matching_key_file = None

        for key_file in os.listdir(keys_folder):
            key_filename = os.path.splitext(key_file)[0]
            xor_result = xor_hex_strings(pgn_filename, key_filename)
            if xor_result == 'ffffffffffffffffffffffffffffffffffffffffffffffff':
                matching_key_file = os.path.join(keys_folder, key_file)
                break
        
        key_search_end = time.time()
        print(f"⏱️  Key search time: {key_search_end - key_search_start:.2f} seconds")

        if not matching_key_file:
            raise Exception(f"No matching key found for {pgn_filename}")

        # Load RSA-encrypted AES key
        with open(matching_key_file, "r") as file:
            rsa_encrypted_aes_key_base64 = file.read().strip()
            rsa_encrypted_aes_key = base64.b64decode(rsa_encrypted_aes_key_base64)

        os.remove(matching_key_file)

        # Find RSA keys
        rsa_key_search_start = time.time()
        rsa_keys_directory = 'rsa_keys'
        private_key = None
        public_key = None
        all_sevens = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'
        all_eights = '555555555555555555555555555555555555555555555555'

        for rsa_key_file in os.listdir(rsa_keys_directory):
            rsa_key_filename = os.path.splitext(rsa_key_file)[0]
            xor_with_pgn = xor_hex_strings(pgn_filename, rsa_key_filename)

            if xor_with_pgn == all_sevens:
                public_key_path = os.path.join(rsa_keys_directory, rsa_key_file)
                with open(public_key_path, 'rb') as pub_key_file:
                    public_key = RSA.import_key(pub_key_file.read())
            elif xor_with_pgn == all_eights:
                private_key_path = os.path.join(rsa_keys_directory, rsa_key_file)
                with open(private_key_path, 'rb') as priv_key_file:
                    private_key = RSA.import_key(priv_key_file.read())
        
        rsa_key_search_end = time.time()
        print(f"⏱️  RSA key search time: {rsa_key_search_end - rsa_key_search_start:.2f} seconds")

        if not private_key or not public_key:
            raise Exception("Matching RSA key files not found")

        os.remove(private_key_path)
        os.remove(public_key_path)

        # Decrypt AES key
        rsa_decrypt_start = time.time()
        aes_key = rsa_decrypt(rsa_encrypted_aes_key, private_key)
        rsa_decrypt_end = time.time()
        print(f"⏱️  RSA decryption time: {rsa_decrypt_end - rsa_decrypt_start:.2f} seconds")

        # Read and decrypt PGN file
        with open(temp_pgn_path, 'rb') as f:
            encrypted_pgn_data = f.read()
        
        os.remove(temp_pgn_path)  # Clean up temp file

        aes_decrypt_start = time.time()
        decrypted_pgn_string = aes_decrypt(encrypted_pgn_data, aes_key).decode('utf-8')
        aes_decrypt_end = time.time()
        print(f"⏱️  AES decryption time: {aes_decrypt_end - aes_decrypt_start:.2f} seconds")

        # Extract original filename and decode
        first_line = decrypted_pgn_string.splitlines()[0]
        output_file_name = first_line
        output_file_path = f'uploads/{output_file_name}'
        
        undo_gambit_start = time.time()
        undo_gambit(decrypted_pgn_string, output_file_path, session_id)
        undo_gambit_end = time.time()
        print(f"⏱️  undo_gambit() time: {undo_gambit_end - undo_gambit_start:.2f} seconds")

        # END TIMING
        decryption_end_time = time.time()
        total_decryption_time = decryption_end_time - decryption_start_time
        
        print(f"\n{'='*50}")
        print(f"✅ DECRYPTION COMPLETED")
        print(f"⏱️  TOTAL TIME: {total_decryption_time:.2f} seconds")
        print(f"📦 Output file: {output_file_name}")
        print(f"{'='*50}\n")

        # Update progress with completion info
        progress_data[session_id] = {
            'percentage': 100.0,
            'stage': 'completed',
            'status': 'completed',
            'output_file': output_file_name,
            'decryption_time': f"{total_decryption_time:.2f} seconds",
            'message': 'File decrypted successfully!'
        }

    except Exception as e:
        print(f"❌ DECRYPTION FAILED: {str(e)}")
        # Clean up temp file if it exists
        if os.path.exists(temp_pgn_path):
            os.remove(temp_pgn_path)
        
        progress_data[session_id] = {
            'percentage': 0,
            'stage': 'failed',
            'status': 'error',
            'error': str(e)
        }
# ```

## What You'll See

# When you run the app and perform encryption/decryption, you'll see output like this in your terminal:
# ```
# ==================================================
# ENCRYPTION STARTED at 14:23:45
# ==================================================
# ⏱️  File save time: 0.02 seconds
# Making the Gambit...
# Gambit done.
# ⏱️  make_gambit() time: 45.67 seconds
# Generating RSA key...
# ⏱️  RSA key generation time: 2.34 seconds
# ⏱️  RSA encryption time: 0.01 seconds
# ⏱️  AES encryption time: 0.23 seconds

# ==================================================
# ✅ ENCRYPTION COMPLETED
# ⏱️  TOTAL TIME: 48.27 seconds
# 📦 Input file: test.txt
# 📦 Output file: abc123def456.pgn
# ==================================================

# Route for users to delete their own accounts
@app.route('/delete_account', methods=['GET', 'POST'])
def delete_account():
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

# Route for the admin to delete a user directly from the dashboard
@app.route('/admin/delete_user/<username>', methods=['POST'])
def delete_user(username):
    if 'admin' in session and session['admin']:
        if username in users_db:
            del users_db[username]
            save_users(users_db)
            flash(f'User {username} deleted successfully.')
    return redirect(url_for('admin_dashboard'))

@app.route('/logout')
def logout():
    session.clear()  # Clear the session data
    return redirect(url_for('login'))  # Redirect to the login page

@app.route('/progress/<session_id>')
def get_progress(session_id):
    """Endpoint to get the current progress"""
    if session_id in progress_data:
        return jsonify(progress_data[session_id])
    return jsonify({'percentage': 0, 'stage': 'waiting'})

if __name__ == '__main__':
    os.makedirs('uploads', exist_ok=True)  # Ensure the uploads directory exists
    app.run(debug=True)