# Queen's Gambit

A Flask-based web application that uses chess game notation (PGN) for steganographic data hiding. This application encodes any file into realistic chess games and securely encrypts the output using hybrid RSA-4096 and AES-256 encryption.

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Usage](#usage)
- [Security Architecture](#security-architecture)
- [Technical Deep Dive](#technical-deep-dive)
- [API Endpoints](#api-endpoints)
- [File Structure](#file-structure)

## Overview

This application implements a sophisticated steganography technique that hides arbitrary data within chess game notation. The core concept is to encode binary data from any file into a sequence of legal chess moves, making the data appear as legitimate chess games in PGN (Portable Game Notation) format.

## Features

- **Steganographic Encoding**: Convert any file into chess PGN notation
- **Hybrid Encryption**: RSA-4096 for key exchange, AES-256 for data encryption
- **User Authentication**: Secure signup/login with email OTP verification
- **Admin Dashboard**: User management interface
- **Secure Key Management**: XOR-based filename obfuscation for key storage
- **Self-Contained Decryption**: All necessary keys stored securely for later retrieval

## How It Works

### High-Level Process Flow

```
Upload File → Binary Conversion → Chess Encoding → AES Encryption → Key Storage → Download
                                                         ↓
Download Encrypted PGN → Key Retrieval → RSA Decryption → AES Decryption → Chess Decoding → Original File
```

### Detailed Step-by-Step Flow

#### Encoding Process (Upload)

1. **File Upload**
   - User uploads any file through the web interface
   - File is saved temporarily in the `uploads/` directory

2. **Binary to Chess Conversion (`make_gambit`)**
   - File is read as binary data (array of bytes)
   - Each byte is converted to 8 bits
   - Algorithm simulates chess games where move selection encodes the binary data:
     - Generate all legal moves in current position
     - Calculate how many bits needed to represent move indices (log₂ of move count)
     - Extract corresponding bits from file data
     - Match extracted bits to a move's binary index
     - Play that move on the board
   - When game ends (checkmate, stalemate, or insufficient moves), start a new game
   - Random metadata added to each game (players, ratings, locations, etc.)
   - Process continues until all file bits are encoded

3. **Key Generation**
   - Generate random 32-byte AES-256 key for file encryption
   - Generate 4096-bit RSA key pair (public and private keys)

4. **Filename Generation**
   - Generate random 24-byte value for key identification
   - Convert to hex string (48 characters)
   - Use XOR operations to create related filenames:
     - Base filename (XOR with 0xFF): Used for encrypted PGN file
     - Public key filename: XOR base with '1' repeated (48 chars)
     - Private key filename: XOR base with 'a' repeated (48 chars)
     - AES key filename: Original 24-byte hex value

5. **Encryption**
   - Original filename prepended to PGN data
   - PGN + filename encrypted with AES-256-CBC
   - AES key encrypted with RSA-4096 public key
   - Encrypted AES key saved to `keys/` directory
   - RSA key pair saved to `rsa_keys/` directory
   - Encrypted PGN saved with obfuscated filename

#### Decoding Process (Download/Decrypt)

1. **File Upload**
   - User uploads the encrypted `.pgn` file
   - Extract filename (hex string without extension)

2. **Key Recovery**
   - Search `keys/` directory for matching AES key:
     - XOR each key filename with uploaded filename
     - Match found when result equals 48 'f' characters
   - Search `rsa_keys/` directory for RSA keys:
     - XOR each key filename with uploaded filename
     - Public key: result equals 48 'e' characters
     - Private key: result equals 48 '5' characters

3. **Decryption**
   - Load encrypted AES key from matched file
   - Decrypt AES key using RSA private key
   - Decrypt PGN file using recovered AES key
   - Extract original filename from first line of decrypted data

4. **Chess to Binary Conversion (`undo_gambit`)**
   - Parse decrypted PGN string into game objects
   - For each game and each move:
     - Generate legal moves in current position
     - Find index of the move that was played
     - Convert index to binary representation
     - Calculate required bit length (same logic as encoding)
     - Pad binary string to correct length
     - Accumulate bits into output string
     - When 8 bits accumulated, convert to byte and write
   - Continue until all games processed

5. **File Reconstruction**
   - All decoded bytes written to output file
   - Original file reconstructed with original filename

## Installation

### Prerequisites
- Python 3.8+
- pip package manager

### Dependencies

```bash
pip install flask pycryptodome python-chess
```

### Setup

1. Clone or download the application
2. Install dependencies
3. Create required directories (auto-created on first run):
   - `uploads/`
   - `keys/`
   - `rsa_keys/`
4. Configure email settings in the code:
   ```python
   # Update these in send_otp_email() function
   SMTP_EMAIL = "your_email@gmail.com"
   SMTP_PASSWORD = "your_app_password"
   ```

### Running the Application

```bash
python app.py
```

Access the application at `http://localhost:5000`

## Usage

### User Registration
1. Navigate to signup page
2. Enter username, password, and email
3. Verify email with OTP sent to your inbox
4. Account created upon successful verification

### Encoding a File
1. Log in with credentials
2. OTP sent to registered email
3. Enter OTP to access upload page
4. Select file to encode
5. Click upload - file converted to encrypted PGN
6. Download the generated `.pgn` file

### Decoding a File
1. Upload the encrypted `.pgn` file
2. Original file automatically reconstructed
3. Download recovered file

### Admin Functions
- Login with admin credentials (username: `admin123`, password: `admin123`)
- View all registered users
- Delete user accounts

## Security Architecture

### Encryption Layers

1. **Steganography Layer**
   - Data hidden in chess move sequences
   - Appears as legitimate chess games
   - No obvious indication of hidden data

2. **AES-256 Encryption**
   - Symmetric encryption for PGN data
   - CBC mode with random IV
   - Fast encryption/decryption

3. **RSA-4096 Encryption**
   - Asymmetric encryption for AES key
   - Secure key exchange mechanism
   - High security for key protection

### Key Management

- **Filename Obfuscation**: XOR-based naming prevents casual file association
- **Key Separation**: AES keys and RSA keys stored in separate directories
- **Automatic Cleanup**: Keys deleted after successful decryption
- **No Centralized Storage**: Each encrypted file has unique key set

### Authentication

- **OTP Verification**: Email-based two-factor authentication
- **Session Management**: Secure session handling with random secret keys
- **Password Protection**: User passwords stored (note: should use hashing in production)

## Technical Deep Dive

### Chess Encoding Algorithm

The `make_gambit` function implements an elegant information-theoretic approach:

**Bit Extraction Logic**:
```
For each position:
  legal_moves = count of legal moves
  bits_needed = floor(log₂(legal_moves))
  bits_to_read = min(bits_needed, remaining_bits)
  
  Extract bits_to_read from file data
  Convert to integer
  Select move at that index
  Play move
```

**Key Insights**:
- Uses Shannon's information theory: n moves can encode log₂(n) bits
- More legal moves = more bits encoded per move
- Maximizes data density in chess notation
- Games appear natural with realistic move sequences

### XOR-Based Key Association

The application uses XOR operations for secure filename relationships:

```
base = random_24_bytes().hex()  # 48 hex chars

pgn_filename = base XOR "ff...ff" (48 f's)
key_filename = base  # Original value
pub_key_filename = base XOR "11...11" (48 1's) 
priv_key_filename = base XOR "aa...aa" (48 a's)

Verification:
pgn_filename XOR key_filename = "ff...ff" ✓
pgn_filename XOR pub_key_filename = "ee...ee" ✓
pgn_filename XOR priv_key_filename = "55...55" ✓
```

This creates deterministic but non-obvious relationships between files.

### Padding and Byte Alignment

Critical for correct decoding:
- Move indices padded to required bit length
- Last move in last game: special handling for remaining bits
- Accumulate bits until 8-bit boundary reached
- Convert each byte and write immediately

## API Endpoints

### Public Routes
- `GET/POST /` - Login page
- `GET/POST /signup` - User registration
- `GET/POST /verify_signup_otp` - OTP verification for signup
- `POST /verify_otp` - OTP verification for login
- `GET/POST /delete_account` - Self-service account deletion
- `GET /logout` - Session termination

### Authenticated Routes
- `GET/POST /upload` - File upload and encoding
- `POST /decrypt_file` - File decryption and decoding
- `GET /uploads/<filename>` - Download encoded/decoded files

### Admin Routes
- `GET/POST /admin_dashboard` - User management interface
- `POST /admin/delete_user/<username>` - Delete specific user

## File Structure

```
project/
├── app.py                 # Main application file
├── users.json            # User database (auto-generated)
├── templates/            # HTML templates
│   ├── login.html
│   ├── signup.html
│   ├── verify_otp.html
│   ├── upload.html
│   ├── admin_dashboard.html
│   └── delete_account.html
├── uploads/              # Temporary file storage
├── keys/                 # Encrypted AES keys
└── rsa_keys/            # RSA key pairs
```

## Important Notes

### Security Considerations (Production)
- **Password Hashing**: Currently stores plaintext passwords - implement bcrypt/argon2
- **HTTPS**: Use SSL/TLS in production
- **Email Security**: Use environment variables for SMTP credentials
- **Rate Limiting**: Add protection against brute force attacks
- **Input Validation**: Strengthen file upload validation
- **Session Security**: Configure secure session cookies

### Performance
- RSA-4096 key generation takes 2-5 seconds
- Large files produce many chess games
- Encoding/decoding time scales with file size
- AES encryption/decryption is fast

### Limitations
- Chess games have natural length limits
- Very large files create numerous games
- RSA key generation is CPU-intensive
- Requires email server configuration

## License

This application is provided as-is for educational purposes.

## Acknowledgments

- Uses `python-chess` library for chess game simulation
- Implements PGN (Portable Game Notation) standard
- Based on information-theoretic steganography principles