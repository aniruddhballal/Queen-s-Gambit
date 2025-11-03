"""
File processing utilities for encryption and decryption operations.
Handles the complete encryption and decryption workflows.
"""

import os
import time
import base64
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA

from crypto_utils import (
    aes_encrypt, aes_decrypt, rsa_encrypt, rsa_decrypt, 
    generate_rsa_keypair, xor_hex_strings
)
from chess_encoder import make_gambit
from chess_decoder import undo_gambit


def process_encryption(uploaded_file_path, original_filename, session_id, progress_data):
    """
    Background thread function to handle complete encryption workflow.
    
    Args:
        uploaded_file_path: str - Path to uploaded file
        original_filename: str - Original name of the file
        session_id: str - Session ID for progress tracking
        progress_data: dict - Dictionary to store progress updates
    """
    try:
        # START TIMING
        encryption_start_time = time.time()
        print(f"\n{'='*50}")
        print(f"ENCRYPTION STARTED at {time.strftime('%H:%M:%S')}")
        print(f"{'='*50}")

        # Call the encode function to get PGN
        gambit_start = time.time()
        encoded_pgn = make_gambit(uploaded_file_path, session_id, progress_data)
        gambit_end = time.time()
        print(f"⏱️  make_gambit() time: {gambit_end - gambit_start:.2f} seconds")

        encoded_pgn = original_filename + '\n' + encoded_pgn

        # Generate AES key
        aes_key = get_random_bytes(32)

        # Generate RSA keys
        print("Generating RSA key...")
        tgen1 = time.time()
        rsa_key = generate_rsa_keypair(4096)
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


def process_decryption(temp_pgn_path, original_filename, session_id, progress_data):
    """
    Background thread function to handle complete decryption workflow.
    
    Args:
        temp_pgn_path: str - Path to temporary PGN file
        original_filename: str - Original filename of the PGN
        session_id: str - Session ID for progress tracking
        progress_data: dict - Dictionary to store progress updates
    """
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
        undo_gambit(decrypted_pgn_string, output_file_path, session_id, progress_data)
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