import base64
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from config import Config

class CryptoService:
    @staticmethod
    def generate_rsa_keys():
        print("Generating RSA key...")
        import time
        tgen1 = time.time()
        rsa_key = RSA.generate(Config.RSA_KEY_SIZE)
        public_key = rsa_key.publickey()
        tgen2 = time.time()
        print(f"RSA key generated in {tgen2-tgen1:.2f} seconds.")
        return rsa_key, public_key
    
    @staticmethod
    def generate_aes_key():
        return get_random_bytes(Config.AES_KEY_SIZE)
    
    @staticmethod
    def aes_encrypt(data, key):
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        iv = cipher.iv
        return base64.b64encode(iv + ct_bytes)
    
    @staticmethod
    def aes_decrypt(enc_data, key):
        enc_data = base64.b64decode(enc_data)
        iv = enc_data[:AES.block_size]
        ct = enc_data[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), AES.block_size)
    
    @staticmethod
    def rsa_encrypt(data, public_key):
        cipher = PKCS1_OAEP.new(public_key)
        return cipher.encrypt(data)
    
    @staticmethod
    def rsa_decrypt(encrypted_data, private_key):
        cipher = PKCS1_OAEP.new(private_key)
        return cipher.decrypt(encrypted_data)