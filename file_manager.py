import os
import base64
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from config import Config

class FileManager:
    @staticmethod
    def ensure_directories():
        os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
        os.makedirs(Config.KEYS_FOLDER, exist_ok=True)
        os.makedirs(Config.RSA_KEYS_FOLDER, exist_ok=True)
    
    @staticmethod
    def xor_hex_strings(hex1, hex2):
        max_length = max(len(hex1), len(hex2))
        hex1 = hex1.zfill(max_length)
        hex2 = hex2.zfill(max_length)
        return ''.join(format(int(a, 16) ^ int(b, 16), 'x') for a, b in zip(hex1, hex2))
    
    @staticmethod
    def xor_with_hex_string(original_hex, target_hex):
        return ''.join(format(int(a, 16) ^ int(b, 16), 'x') for a, b in zip(original_hex, target_hex))
    
    @staticmethod
    def generate_key_filenames():
        keys_filename = get_random_bytes(24)
        keys_filename_hex = keys_filename.hex()
        keys_xor_result = bytes(b ^ 0xff for b in keys_filename)
        keys_xor_hex_str = keys_xor_result.hex()
        
        all_sevens = '1' * len(keys_filename_hex)
        all_eights = 'a' * len(keys_filename_hex)
        
        public_key_filename_hex = FileManager.xor_with_hex_string(keys_filename_hex, all_sevens)
        private_key_filename_hex = FileManager.xor_with_hex_string(keys_filename_hex, all_eights)
        
        return {
            'keys_filename_hex': keys_filename_hex,
            'keys_xor_hex_str': keys_xor_hex_str,
            'public_key_filename_hex': public_key_filename_hex,
            'private_key_filename_hex': private_key_filename_hex
        }
    
    @staticmethod
    def save_rsa_keys(rsa_key, public_key, filenames):
        private_key_path = os.path.join(Config.RSA_KEYS_FOLDER, f"{filenames['private_key_filename_hex']}.pem")
        with open(private_key_path, 'wb') as f:
            f.write(rsa_key.export_key())
        
        public_key_path = os.path.join(Config.RSA_KEYS_FOLDER, f"{filenames['public_key_filename_hex']}.pem")
        with open(public_key_path, 'wb') as f:
            f.write(public_key.export_key())
    
    @staticmethod
    def save_encrypted_aes_key(encrypted_aes_key, filename_hex):
        keys_filename_string = os.path.join(Config.KEYS_FOLDER, f"{filename_hex}.txt")
        with open(keys_filename_string, "w") as file:
            file.write(base64.b64encode(encrypted_aes_key).decode('utf-8'))
    
    @staticmethod
    def find_matching_key_file(pgn_filename):
        for key_file in os.listdir(Config.KEYS_FOLDER):
            key_filename = os.path.splitext(key_file)[0]
            xor_result = FileManager.xor_hex_strings(pgn_filename, key_filename)
            if xor_result == 'ffffffffffffffffffffffffffffffffffffffffffffffff':
                return os.path.join(Config.KEYS_FOLDER, key_file)
        return None
    
    @staticmethod
    def find_rsa_keys(pgn_filename):
        all_sevens = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'
        all_eights = '555555555555555555555555555555555555555555555555'
        
        private_key = None
        public_key = None
        private_key_path = None
        public_key_path = None
        
        for rsa_key_file in os.listdir(Config.RSA_KEYS_FOLDER):
            rsa_key_filename = os.path.splitext(rsa_key_file)[0]
            xor_with_pgn = FileManager.xor_hex_strings(pgn_filename, rsa_key_filename)

            if xor_with_pgn == all_sevens:
                public_key_path = os.path.join(Config.RSA_KEYS_FOLDER, rsa_key_file)
                with open(public_key_path, 'rb') as pub_key_file:
                    public_key = RSA.import_key(pub_key_file.read())
            elif xor_with_pgn == all_eights:
                private_key_path = os.path.join(Config.RSA_KEYS_FOLDER, rsa_key_file)
                with open(private_key_path, 'rb') as priv_key_file:
                    private_key = RSA.import_key(priv_key_file.read())
        
        return private_key, public_key, private_key_path, public_key_path