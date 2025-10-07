from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

# Function to encrypt data with AES
def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = cipher.iv
    return base64.b64encode(iv + ct_bytes)

# Function to decrypt AES-encrypted data
def aes_decrypt(enc_data, key):
    enc_data = base64.b64decode(enc_data)
    iv = enc_data[:AES.block_size]
    ct = enc_data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

# Function to encrypt data with DES
def des_encrypt(data, key):
    cipher = DES.new(key, DES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, DES.block_size))
    iv = cipher.iv
    return base64.b64encode(iv + ct_bytes)

# Function to decrypt DES-encrypted data
def des_decrypt(enc_data, key):
    enc_data = base64.b64decode(enc_data)
    iv = enc_data[:DES.block_size]
    ct = enc_data[DES.block_size:]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), DES.block_size)

# Read the PGN file
with open('encrypted.pgn', 'rb') as f:
    pgn_data = f.read()

# Define keys for AES and DES (must be 16 bytes for AES, 8 bytes for DES)
aes_key = get_random_bytes(16)
des_key = get_random_bytes(8)

# First layer of encryption with AES
aes_encrypted_pgn = aes_encrypt(pgn_data, aes_key)

# Second layer of encryption with DES
double_encrypted_pgn = des_encrypt(aes_encrypted_pgn, des_key)

# Save the doubly encrypted data to a new file
with open('double_encrypted.pgn', 'wb') as f:
    f.write(double_encrypted_pgn)

print("PGN file successfully encrypted with AES and DES.")