from flask import Blueprint, render_template, request, jsonify, send_from_directory
import os
import base64
from config import Config
from chess_encoder import ChessEncoder
from crypto_utils import CryptoService
from file_manager import FileManager

file_bp = Blueprint('file', __name__)

@file_bp.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        uploaded_file = request.files['file']
        if uploaded_file.filename != '':
            FileManager.ensure_directories()
            uploaded_file_path = os.path.join(Config.UPLOAD_FOLDER, uploaded_file.filename)
            uploaded_file.save(uploaded_file_path)

            encoded_pgn = ChessEncoder.make_gambit(uploaded_file_path)
            encoded_pgn = uploaded_file.filename + '\n' + encoded_pgn

            aes_key = CryptoService.generate_aes_key()
            rsa_key, public_key = CryptoService.generate_rsa_keys()

            filenames = FileManager.generate_key_filenames()
            FileManager.save_rsa_keys(rsa_key, public_key, filenames)

            rsa_encrypted_aes_key = CryptoService.rsa_encrypt(aes_key, public_key)
            FileManager.save_encrypted_aes_key(rsa_encrypted_aes_key, filenames['keys_filename_hex'])

            aes_encrypted_pgn = CryptoService.aes_encrypt(encoded_pgn.encode('utf-8'), aes_key)

            pgn_file_name = f"{filenames['keys_xor_hex_str']}.pgn"
            pgn_file_path = os.path.join(Config.UPLOAD_FOLDER, pgn_file_name)
            with open(pgn_file_path, "wb") as f:
                f.write(aes_encrypted_pgn)

            return jsonify({"message": "File converted successfully!", "pgn_file": pgn_file_name})

    return render_template('upload.html')

@file_bp.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(Config.UPLOAD_FOLDER, filename)

@file_bp.route('/decrypt_file', methods=['POST'])
def decrypt_file():
    pgn_file = request.files['pgn_file']
    pgn_filename = os.path.splitext(pgn_file.filename)[0]

    matching_key_file = FileManager.find_matching_key_file(pgn_filename)
    if not matching_key_file:
        return jsonify({"error": f"No matching key found for {pgn_filename}"}), 400

    with open(matching_key_file, "r") as file:
        rsa_encrypted_aes_key_base64 = file.read().strip()
        rsa_encrypted_aes_key = base64.b64decode(rsa_encrypted_aes_key_base64)

    os.remove(matching_key_file)

    private_key, public_key, private_key_path, public_key_path = FileManager.find_rsa_keys(pgn_filename)

    if not private_key or not public_key:
        return jsonify({"error": "Matching RSA key files not found."}), 400

    os.remove(private_key_path)
    os.remove(public_key_path)

    try:
        aes_key = CryptoService.rsa_decrypt(rsa_encrypted_aes_key, private_key)
    except Exception as e:
        return jsonify({"error": f"Failed to decrypt AES key: {str(e)}"}), 500

    encrypted_pgn_data = pgn_file.read()
    try:
        decrypted_pgn_string = CryptoService.aes_decrypt(encrypted_pgn_data, aes_key).decode('utf-8')
    except Exception as e:
        return jsonify({"error": f"Failed to decrypt the PGN file: {str(e)}"}), 500

    first_line = decrypted_pgn_string.splitlines()[0]
    output_file_name = first_line
    output_file_path = f'{Config.UPLOAD_FOLDER}/{output_file_name}'
    ChessEncoder.undo_gambit(decrypted_pgn_string, output_file_path)

    return jsonify({"message": "File decrypted successfully!", "output_file": output_file_name})