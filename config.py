import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', os.urandom(24))
    ADMIN_USERNAME = os.getenv('ADMIN_USERNAME')
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')
    
    SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
    SMTP_EMAIL = os.getenv('SMTP_EMAIL')
    SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
    
    UPLOAD_FOLDER = 'uploads'
    KEYS_FOLDER = 'keys'
    RSA_KEYS_FOLDER = 'rsa_keys'
    USERS_DB_FILE = 'users.json'
    
    RSA_KEY_SIZE = 4096
    AES_KEY_SIZE = 32
    OTP_LENGTH = 6