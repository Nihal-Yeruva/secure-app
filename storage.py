import json
import os
from cryptography.fernet import Fernet
from config import Config


class EncryptedStorage:
    """Fernet-based encrypted JSON file storage."""

    def __init__(self, key_file=None):
        key_file = key_file or Config.ENCRYPTION_KEY_FILE
        os.makedirs(os.path.dirname(key_file), exist_ok=True)
        try:
            with open(key_file, 'rb') as f:
                self.key = f.read()
        except FileNotFoundError:
            self.key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(self.key)
        self.cipher = Fernet(self.key)

    def save_encrypted(self, filepath, data):
        """Encrypt and save JSON data."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        encrypted = self.cipher.encrypt(json.dumps(data).encode())
        with open(filepath, 'wb') as f:
            f.write(encrypted)

    def load_encrypted(self, filepath):
        """Load and decrypt JSON data. Returns {} if file doesn't exist."""
        if not os.path.exists(filepath):
            return {}
        with open(filepath, 'rb') as f:
            encrypted = f.read()
        decrypted = self.cipher.decrypt(encrypted)
        return json.loads(decrypted.decode())

    def encrypt_bytes(self, data: bytes) -> bytes:
        return self.cipher.encrypt(data)

    def decrypt_bytes(self, data: bytes) -> bytes:
        return self.cipher.decrypt(data)


class JSONStore:
    """Plain JSON store for non-sensitive metadata."""

    @staticmethod
    def load(filepath):
        if not os.path.exists(filepath):
            return {}
        with open(filepath, 'r') as f:
            return json.load(f)

    @staticmethod
    def save(filepath, data):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)





enc_storage = EncryptedStorage()
