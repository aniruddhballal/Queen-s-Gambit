from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session
import os
from math import log2
from chess import Board, pgn  # Make sure you have the chess library
import random  # For your random_metadata function
from util import to_binary_string
from flask import jsonify
import json

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

def random_user_id():
    return f"{random.randint(1000000, 9999999)}"

def random_metadata():
    events = ["Friendly Match", "Tournament", "Casual Game", "Championship"]
    locations = ["Local Club", "Online", "City Park", "University Hall", "Community Center"]
    openings = ["Sicilian Defense", "French Defense", "Caro-Kann", "Ruy Lopez", "Italian Game"]
    ratings = [random.randint(1200, 2800) for _ in range(2)]  # Random ratings for two players
    results = ["1-0", "0-1", "1/2-1/2", "*"]  # Possible outcomes

    return {
        "Event": random.choice(events),
        "Site": random.choice(locations),
        "Date": f"{random.randint(2000, 2023)}.{random.randint(1, 12):02d}.{random.randint(1, 31):02d}",
        "Round": str(random.randint(1, 10)),
        "White": random_user_id(),
        "Black": random_user_id(),
        "Opening": random.choice(openings),
        "WhiteElo": str(ratings[0]),
        "BlackElo": str(ratings[1]),
        "Result": random.choice(results),
        "Annotator": "AI Assistant",
        "Variation": random.choice(["Main Line", "Alternative Line", "Quiet Move"]),
        "EventDate": f"{random.randint(2000, 2023)}.{random.randint(1, 12):02d}.{random.randint(1, 31):02d}",
        "TimeControl": random.choice(["5+0", "10+0", "15+10", "30+0"])
    }

def encode(file_path: str):
    # Read binary of file
    print("Reading file...")
    file_bytes = list(open(file_path, "rb").read())

    # Record number of bits in file
    file_bits_count = len(file_bytes) * 8

    # Convert file to chess moves
    print("\nEncoding file...")
    output_pgns = []
    file_bit_index = 0
    chess_board = Board()

    while True:
        legal_moves = list(chess_board.generate_legal_moves())
        move_bits = {}
        max_binary_length = min(int(log2(len(legal_moves))), file_bits_count - file_bit_index)

        for index, legal_move in enumerate(legal_moves):
            move_binary = to_binary_string(index, max_binary_length)
            if len(move_binary) > max_binary_length:
                break
            move_bits[legal_move.uci()] = move_binary

        closest_byte_index = file_bit_index // 8
        file_chunk_pool = "".join([
            to_binary_string(byte, 8)
            for byte in file_bytes[closest_byte_index:closest_byte_index + 2]
        ])

        next_file_chunk = file_chunk_pool[file_bit_index % 8:file_bit_index % 8 + max_binary_length]

        for move_uci in move_bits:
            move_binary = move_bits[move_uci]
            if move_binary == next_file_chunk:
                chess_board.push_uci(move_uci)
                break

        file_bit_index += max_binary_length
        eof_reached = file_bit_index >= file_bits_count

        if (
            chess_board.legal_moves.count() <= 1
            or chess_board.is_insufficient_material()
            or chess_board.can_claim_draw()
            or eof_reached
        ):
            pgn_board = pgn.Game()
            # Add randomized metadata
            metadata = random_metadata()
            for key, value in metadata.items():
                pgn_board.headers[key] = value
            pgn_board.add_line(chess_board.move_stack)
            output_pgns.append(str(pgn_board))
            chess_board.reset()

        if eof_reached:
            break

    print(f"\nSuccessfully converted file to PGN with {len(output_pgns)} game(s) ")
    return "\n\n".join(output_pgns)

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