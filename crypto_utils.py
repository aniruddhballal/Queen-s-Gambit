"""
Cryptography utilities for encryption and decryption operations.
Handles AES-256 and RSA-4096 encryption/decryption.
"""

import base64
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad


def aes_encrypt(data, key):
    """
    Encrypt data with AES-256 in CBC mode.
    
    Args:
        data: bytes - Data to encrypt
        key: bytes - 32-byte AES key
        
    Returns:
        Base64-encoded encrypted data with IV prepended
    """
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = cipher.iv
    return base64.b64encode(iv + ct_bytes)


def aes_decrypt(enc_data, key):
    """
    Decrypt AES-256 encrypted data.
    
    Args:
        enc_data: Base64-encoded encrypted data with IV
        key: bytes - 32-byte AES key
        
    Returns:
        Decrypted data as bytes
    """
    enc_data = base64.b64decode(enc_data)
    iv = enc_data[:AES.block_size]
    ct = enc_data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)


def rsa_encrypt(data, public_key):
    """
    Encrypt data with RSA-4096 using OAEP padding.
    
    Args:
        data: bytes - Data to encrypt (typically AES key)
        public_key: RSA public key object
        
    Returns:
        Encrypted data as bytes
    """
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(data)


def rsa_decrypt(encrypted_data, private_key):
    """
    Decrypt data with RSA-4096 using OAEP padding.
    
    Args:
        encrypted_data: bytes - Encrypted data
        private_key: RSA private key object
        
    Returns:
        Decrypted data as bytes
    """
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(encrypted_data)


def generate_rsa_keypair(bits=4096):
    """
    Generate RSA key pair.
    
    Args:
        bits: int - Key size in bits (default 4096)
        
    Returns:
        RSA key object containing both public and private keys
    """
    return RSA.generate(bits)


def xor_hex_strings(hex1, hex2):
    """
    XOR two hex strings and return the result.
    
    Args:
        hex1: str - First hex string
        hex2: str - Second hex string
        
    Returns:
        XOR result as hex string
    """
    max_length = max(len(hex1), len(hex2))
    hex1 = hex1.zfill(max_length)
    hex2 = hex2.zfill(max_length)
    return ''.join(format(int(a, 16) ^ int(b, 16), 'x') for a, b in zip(hex1, hex2))