from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pyserpent import Serpent
from base64 import b64decode
import os
import argon2
import binascii

ENCRYPTION_VERSION = "V2.0"  


class EncryptionHandler:
    def __init__(self, argon2_params):
        # ZMIANA: Przyjmujemy słownik z parametrami, a nie 'level'
        if not isinstance(argon2_params, dict) or not all(k in argon2_params for k in ["m", "t", "p"]):
            raise ValueError(f"Nieprawidłowe parametry Argon2. Oczekiwano słownika z kluczami 'm', 't', 'p'. Otrzymano: {argon2_params}")
        
        self.argon2_params = argon2_params # ZMIANA: Zapisz parametry
        self.supported_levels = ["low", "normal", "high"] # Może zostać dla kompatybilności

    def fix_key(self, key):
        """Normalize key input into raw bytes"""
        # ... (ta funkcja zostaje bez zmian) ...
        if isinstance(key, str):
            try:
                return b64decode(key)
            except Exception:
                if all(c in '0123456789abcdefABCDEF' for c in key) and len(key) % 2 == 0:
                    return bytes.fromhex(key)
                return key.encode("utf-8")
        return key

    def generate_key(self, password, salt):
        """Generate encryption key with Argon2ID using parameters from __init__"""
        # ZMIANA: Usuń stary, hardkodowany słownik 'params'
        
        # ZMIANA: Użyj parametrów przekazanych w __init__
        level_params = self.argon2_params 
        
        # Use low-level Argon2 API to directly hash with our salt
        argon2_hash = argon2.low_level.hash_secret_raw(
            secret=password.encode(),
            salt=salt,
            time_cost=level_params["t"],
            memory_cost=level_params["m"],
            parallelism=level_params["p"],
            hash_len=32,
            type=argon2.Type.ID
        )
        
        return argon2_hash

    def encrypt_data(self, key, nonce, data):
        """Encrypt data with proper key handling for all levels using AEAD."""
        key = self.fix_key(key)

        aesgcm = AESGCM(key)
        return aesgcm.encrypt(nonce, data, None)  

    def decrypt_data(self, key, nonce, encrypted_data):
        """Decrypt data with proper key handling for all levels using AEAD."""
        key = self.fix_key(key)

        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, encrypted_data, None)

    def get_nonce_size(self):
        """Get nonce size for GCM (96 bits recommended)"""
        return 12  # 96 bits for GCM

    def get_salt_size(self):
        """Get salt size for Argon2"""
        return 16  # 128-bit salt

    def get_key_size(self):
        """Get required key size for current level"""
        return 32 
    def create_cipher(self, key, nonce):
        """Create cipher based on encryption level - not used for AEAD"""
        raise NotImplementedError("AEAD mode doesn't use traditional cipher objects")
