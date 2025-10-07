from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

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

# Generate RSA key pair (private and public keys)
def generate_rsa_keypair():
    key = RSA.generate(4096)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key

# Read the PGN file
with open('encrypted.pgn', 'rb') as f:
    pgn_data = f.read()

# Generate AES-256 key (32 bytes)
aes_key = get_random_bytes(32)
# Encrypt the PGN data with AES-256
aes_encrypted_pgn = aes_encrypt(pgn_data, aes_key)
# Generate RSA key pair (4096 bits)
private_key, public_key = generate_rsa_keypair()

# Encrypt the AES key using RSA-4096
encrypted_aes_key = rsa_encrypt(aes_key, public_key)

# Save the AES-encrypted PGN data and the encrypted AES key
with open('aes_encrypted_pgn.pgn', 'wb') as f:
    f.write(aes_encrypted_pgn)

with open('rsa_encrypted_aes_key.bin', 'wb') as f:
    f.write(encrypted_aes_key)

print("PGN file successfully encrypted with AES-256 and the AES key encrypted with RSA-4096.")

# Example Decryption Process:
# To decrypt, we would use the RSA private key to decrypt the AES key and then use the AES key to decrypt the PGN file

# Decrypt the AES key using RSA private key
with open('rsa_encrypted_aes_key.bin', 'rb') as f:
    encrypted_aes_key = f.read()

aes_key_decrypted = rsa_decrypt(encrypted_aes_key, private_key)

# Decrypt the PGN data using the decrypted AES key
with open('aes_encrypted_pgn.pgn', 'rb') as f:
    aes_encrypted_pgn = f.read()

pgn_data_decrypted = aes_decrypt(aes_encrypted_pgn, aes_key_decrypted)

# Save the decrypted PGN file
with open('decrypted_pgn.pgn', 'wb') as f:
    f.write(pgn_data_decrypted)

print("PGN file successfully decrypted.")