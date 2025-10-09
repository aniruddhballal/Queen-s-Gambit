from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash

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

# Function to encrypt data with ECC-521 (used for the AES key)
def ecc_encrypt(data, public_key):
    shared_key = public_key.exchange(ec.ECDH())  # ECDH key exchange
    derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data', backend=default_backend()).derive(shared_key)
    return aes_encrypt(data, derived_key)  # Use derived key to encrypt the AES key

# Function to decrypt data with ECC-521 (used to decrypt the AES key)
def ecc_decrypt(encrypted_data, private_key):
    shared_key = private_key.exchange(ec.ECDH(), private_key.public_key())  # ECDH key exchange
    derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data', backend=default_backend()).derive(shared_key)
    return aes_decrypt(encrypted_data, derived_key)  # Use derived key to decrypt the AES key

# Example key pair generation
def generate_ecc_key_pair():
    private_key = ec.generate_private_key(ec.SECP521R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# Serialize and deserialize functions for ECC keys
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(pem_public_key):
    return serialization.load_pem_public_key(pem_public_key, backend=default_backend())

def serialize_private_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

def deserialize_private_key(pem_private_key):
    return serialization.load_pem_private_key(pem_private_key, password=None, backend=default_backend())

# Example usage
private_key, public_key = generate_ecc_key_pair()
aes_key = b'sixteen byte key'  # Example AES key

# Encrypt the AES key using ECC-521
encrypted_aes_key = ecc_encrypt(aes_key, public_key)

# Decrypt the AES key using ECC-521
decrypted_aes_key = ecc_decrypt(encrypted_aes_key, private_key)

print("Original AES key:", aes_key)
print("Decrypted AES key:", decrypted_aes_key)
