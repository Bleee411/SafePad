import os
import json
import base64
import stat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pyserpent import serpent_cbc_encrypt, serpent_cbc_decrypt
import argon2
from pathlib import Path

try:
    import keyring
    import keyring.errors
    _HAS_KEYRING = True
except ImportError:
    _HAS_KEYRING = False

# ------------------------------- Konfiguracja Parametrów Argona -------------------------------

class Registryconf:
    # Używamy XDG_CONFIG_HOME zgodnie ze standardem Linux
    CONFIG_DIR = Path.home() / ".config" / "SafePad"
    CONFIG_FILE = CONFIG_DIR / "settings.json"
    ARGON_CONFIG_FILE = CONFIG_DIR / "argon_config.json"
    
    # Nazwa "service" pod jaką hasło do backupów jest przechowywane w
    # systemowym keyringu (GNOME Keyring / KWallet / Secret Service).
    KEYRING_SERVICE = "SafePad"
    KEYRING_USERNAME = "backup_password"
    
    DEFAULT_ARGON_PARAMS = {
        "low": {"m": 16 * 1024, "t": 2, "p": 1},
        "medium": {"m": 64 * 1024, "t": 3, "p": 2},
        "high": {"m": 512 * 1024, "t": 4, "p": 4}
    }
    
    @classmethod
    def _ensure_config_dir(cls):
        """Tworzy katalog konfiguracyjny (jeśli nie istnieje) z restrykcyjnymi
        uprawnieniami 0700, żeby inni użytkownicy tego samego komputera nie
        mogli odczytać plików konfiguracyjnych."""
        cls.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(cls.CONFIG_DIR, stat.S_IRWXU)  # 0700 - tylko właściciel
        except OSError:
            pass
    
    @classmethod
    def _read_config(cls, filepath):
        """Odczytuje plik JSON lub zwraca pusty słownik."""
        try:
            if filepath.exists():
                with open(filepath, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            print(f"Błąd odczytu pliku konfiguracyjnego {filepath}: {e}")
        return {}
    
    @classmethod
    def _write_config(cls, filepath, data):
        """Zapisuje dane do pliku JSON z restrykcyjnymi uprawnieniami (0600)."""
        cls._ensure_config_dir()
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4)
            os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)  # 0600 - tylko właściciel
            return True
        except OSError as e:
            print(f"Błąd zapisu pliku konfiguracyjnego {filepath}: {e}")
            return False
    
    @classmethod
    def save_argon_conf(cls, encryption_level, params):
        """Zapisuje parametry Argon2 dla danego poziomu."""
        all_params = cls._read_config(cls.ARGON_CONFIG_FILE)
        all_params[encryption_level] = params
        return cls._write_config(cls.ARGON_CONFIG_FILE, all_params)
    
    @classmethod
    def load_argon_conf(cls, encryption_level=None):
        """Ładuje parametry Argon2 z pliku konfiguracyjnego."""
        all_params = cls._read_config(cls.ARGON_CONFIG_FILE)
        
        if encryption_level is None:
            # Jeżeli nie podano poziomu, spróbuj wczytać z głównej konfiguracji
            main_settings = cls._read_config(cls.CONFIG_FILE)
            encryption_level = main_settings.get("encryption_level", "medium")
        
        if encryption_level in all_params:
            return all_params[encryption_level]
        else:
            # Zwróć domyślne parametry dla danego poziomu
            return cls.DEFAULT_ARGON_PARAMS.get(encryption_level, cls.DEFAULT_ARGON_PARAMS["medium"])
    
    # ------------------------- METODY DO ZAPISU USTAWIEŃ -------------------------
    
    @classmethod
    def save_settings(cls, settings):
        """Zapisuje ustawienia aplikacji, SCALAJĄC je z już zapisaną
        konfiguracją.
        
        Wcześniej ta metoda całkowicie nadpisywała plik ustawień samym
        przekazanym słownikiem `settings`. Ponieważ SettingsDialog.get_settings()
        zwraca tylko ~10 kluczy widocznych w oknie Ustawień, każde zapisanie
        ustawień (np. samo przełączenie dark mode) bezpowrotnie usuwało inne
        dane trzymane w tym samym pliku, takie jak wyniki ostatniego
        benchmarku Argon2ID (last_benchmark_time/last_benchmark_params)."""
        existing = cls._read_config(cls.CONFIG_FILE)
        existing.update(settings)
        return cls._write_config(cls.CONFIG_FILE, existing)
    
    @classmethod
    def load_settings(cls):
        """Ładuje wszystkie ustawienia aplikacji z pliku JSON."""
        default_settings = {
            "encryption_level": "medium",
            "password_min_length": 8,
            "password_require_upper": True,
            "password_require_lower": True,
            "password_require_number": True,
            "password_require_special": False,
            "dark_mode": True,
            "notifications": True,
        }
        
        loaded_settings = cls._read_config(cls.CONFIG_FILE)
        # Scal załadowane ustawienia z domyślnymi
        default_settings.update(loaded_settings)
        return default_settings
    

    @classmethod
    def get_current_level(cls):
        """Pobiera obecny poziom szyfrowania z głównych ustawień."""
        settings = cls._read_config(cls.CONFIG_FILE)
        return settings.get("encryption_level", "medium")
    
    
    @classmethod
    def save_backup_password(cls, password):
        """Zapisuje własne hasło do backupów sesji.
        
        Przechowywane w systemowym keyringu (GNOME Keyring / KWallet / inny
        backend Secret Service) zamiast w pliku tekstowym zakodowanym base64
        - base64 nie jest szyfrowaniem i jest trywialnie odwracalny przez
        każdego z odczytem do pliku konfiguracyjnego.
        
        Jeśli żaden keyring nie jest dostępny (np. serwer bez sesji
        graficznej / bez usługi Secret Service), używamy zapasowego
        przechowywania w pliku konfiguracyjnym (0600, właściciel-only) -
        wciąż tylko base64, ale to jest już wyjątek, nie reguła."""
        if _HAS_KEYRING:
            try:
                keyring.set_password(cls.KEYRING_SERVICE, cls.KEYRING_USERNAME, password)
                # Upewnij się, że nie został pozostawiony żaden stary wpis fallback
                settings = cls._read_config(cls.CONFIG_FILE)
                if "backup_password" in settings:
                    del settings["backup_password"]
                    cls._write_config(cls.CONFIG_FILE, settings)
                return True
            except Exception as e:
                print(f"Nie można zapisać hasła w keyringu, używam zapasowego pliku: {e}")
        
        # Fallback: brak keyringu
        settings = cls._read_config(cls.CONFIG_FILE)
        encoded_password = base64.b64encode(password.encode('utf-8')).decode('utf-8')
        settings["backup_password"] = encoded_password
        return cls._write_config(cls.CONFIG_FILE, settings)
    
    @classmethod
    def load_backup_password(cls):
        """Wczytuje własne hasło do backupów sesji (keyring, z fallbackiem na plik)."""
        if _HAS_KEYRING:
            try:
                password = keyring.get_password(cls.KEYRING_SERVICE, cls.KEYRING_USERNAME)
                if password:
                    return password
            except Exception as e:
                print(f"Nie można wczytać hasła z keyringu: {e}")
        
        # Fallback: stary/zapasowy wpis w pliku konfiguracyjnym
        settings = cls._read_config(cls.CONFIG_FILE)
        encoded_password = settings.get("backup_password")
        if encoded_password:
            try:
                return base64.b64decode(encoded_password.encode('utf-8')).decode('utf-8')
            except Exception as e:
                print(f"Błąd dekodowania hasła backupu: {e}")
        return None
    
    @classmethod
    def delete_backup_password(cls):
        """Usuwa własne hasło do backupów (przywraca domyślne)."""
        if _HAS_KEYRING:
            try:
                keyring.delete_password(cls.KEYRING_SERVICE, cls.KEYRING_USERNAME)
            except keyring.errors.PasswordDeleteError:
                pass  # nie było zapisane w keyringu - nic do usunięcia
            except Exception as e:
                print(f"Nie można usunąć hasła z keyringu: {e}")
        
        settings = cls._read_config(cls.CONFIG_FILE)
        if "backup_password" in settings:
            del settings["backup_password"]
            return cls._write_config(cls.CONFIG_FILE, settings)
        return True

class EncryptionCEO:
    
    ENCRYPTION_VERSION = "V2.0"
    CASCADE_VERSION = "V3.0"
    SALT_SIZE = 16
    NONCE_SIZE = 12
    SERPENT_KEY_SIZE = 32
    SERPENT_BLOCK_SIZE = 16
    
    def __init__(self, encryption_level=None):
        if encryption_level is None:
            settings = Registryconf.load_settings()
            encryption_level = settings.get("encryption_level", "medium")
        
        self.encryption_level = encryption_level
        self.argon_params = Registryconf.load_argon_conf(self.encryption_level)
        self.use_cascade = (self.encryption_level == "high")
        
    def generate_key(self, password, salt):
        """Generuje klucz AES (256 bit)"""
        try:
            key = argon2.low_level.hash_secret_raw(
                secret=password.encode('utf-8'),
                salt=salt,
                time_cost=self.argon_params['t'],
                memory_cost=self.argon_params['m'],
                parallelism=self.argon_params['p'],
                hash_len=32,
                type=argon2.low_level.Type.ID
            )
            return key
        except Exception as e:
            print(f"Błąd generowania klucza AES: {e}")
            raise
    
    def generate_serpent_key(self, password, salt):
        """Generuje osobny klucz dla Serpent (256 bit)"""
        try:
            different_salt = bytes([b ^ 0xAA for b in salt])
            key = argon2.low_level.hash_secret_raw(
                secret=password.encode('utf-8'),
                salt=different_salt,
                time_cost=self.argon_params['t'],
                memory_cost=self.argon_params['m'],
                parallelism=self.argon_params['p'],
                hash_len=32,
                type=argon2.low_level.Type.ID
            )
            return key
        except Exception as e:
            print(f"Błąd generowania klucza Serpent: {e}")
            raise
    
    @staticmethod
    def _pad_pkcs7(data, block_size=16):
        """Dodaje padding PKCS7"""
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    @staticmethod
    def _unpad_pkcs7(padded_data):
        """Usuwa padding PKCS7"""
        padding_length = padded_data[-1]
        if padding_length < 1 or padding_length > 16:
            raise ValueError("Nieprawidłowy padding")
        return padded_data[:-padding_length]
    
    def encrypt_data(self, password, data):
        """Szyfruje dane AES-GCM lub AES-GCM + Serpent-CBC"""
        if self.use_cascade:
            return self._encrypt_cascade(password, data)
        else:
            return self._encrypt_aes_only(password, data)
    
    def _encrypt_aes_only(self, password, data):
        """Szyfrowanie tylko AES-GCM"""
        salt = os.urandom(self.SALT_SIZE)
        nonce = os.urandom(self.NONCE_SIZE)
        
        key = self.generate_key(password, salt)
        
        aesgcm = AESGCM(key)
        encrypted_data = aesgcm.encrypt(nonce, data, None)
        
        result = (
            self.ENCRYPTION_VERSION.encode('utf-8') +
            salt +
            nonce +
            encrypted_data
        )
        
        return result
    
    def _encrypt_cascade(self, password, data):
        """Szyfrowanie kaskadowe: najpierw AES-GCM, potem Serpent-CBC"""
        # Krok 1: Szyfrowanie AES-GCM
        aes_salt = os.urandom(self.SALT_SIZE)
        aes_nonce = os.urandom(self.NONCE_SIZE)
        aes_key = self.generate_key(password, aes_salt)
        
        aesgcm = AESGCM(aes_key)
        aes_encrypted = aesgcm.encrypt(aes_nonce, data, None)
        
        # Krok 2: Szyfrowanie Serpent-CBC
        serpent_salt = os.urandom(self.SALT_SIZE)
        serpent_iv = os.urandom(self.SERPENT_BLOCK_SIZE)
        serpent_key = self.generate_serpent_key(password, serpent_salt)
        
        # Padding PKCS7
        padded_data = self._pad_pkcs7(aes_encrypted, self.SERPENT_BLOCK_SIZE)
        
        # Szyfrowanie Serpent - IV jako część danych
        # Format: IV(16 bajtów) + dane
        combined_data = serpent_iv + padded_data
        serpent_encrypted = serpent_cbc_encrypt(serpent_key, combined_data)
        
        # Format: V3.0 + AES_SALT(16) + AES_NONCE(12) + SERPENT_SALT(16) + DANE
        # UWAGA: Nie zapisujemy osobno IV, bo jest w zaszyfrowanych danych
        result = (
            self.CASCADE_VERSION.encode('utf-8') +
            aes_salt +
            aes_nonce +
            serpent_salt +
            serpent_encrypted
        )
        
        return result
    
    def decrypt_data(self, password, encrypted_data):
        """Odszyfrowuje dane"""
        if len(encrypted_data) < 4:
            raise ValueError("Dane są za krótkie")
            
        version = encrypted_data[:4].decode('utf-8')
        
        if version == self.CASCADE_VERSION:
            return self._decrypt_cascade(password, encrypted_data)
        elif version == self.ENCRYPTION_VERSION:
            return self._decrypt_aes_only(password, encrypted_data)
        else:
            raise ValueError(f"Nieobsługiwana wersja szyfrowania: {version}")
    
    def _decrypt_aes_only(self, password, encrypted_data):
        """Odszyfrowanie tylko AES-GCM"""
        header_size = 4 + self.SALT_SIZE + self.NONCE_SIZE
        if len(encrypted_data) < header_size:
            raise ValueError("Dane są za krótkie albo uszkodzone")
        
        salt = encrypted_data[4:4 + self.SALT_SIZE]
        nonce = encrypted_data[4 + self.SALT_SIZE:header_size]
        ciphertext = encrypted_data[header_size:]
        
        key = self.generate_key(password, salt)
        aesgcm = AESGCM(key)
        decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
        
        return decrypted_data
    
    def _decrypt_cascade(self, password, encrypted_data):
        """
        Odszyfrowanie kaskadowe: najpierw Serpent-CBC, potem AES-GCM
        Format: V3.0 + AES_SALT(16) + AES_NONCE(12) + SERPENT_SALT(16) + ZASZYFROWANE_DANE
        Zaszyfrowane dane zawierają: IV(16) + AES_ENCRYPTED
        """
        min_length = 4 + self.SALT_SIZE + self.NONCE_SIZE + self.SALT_SIZE + 16
        if len(encrypted_data) < min_length:
            raise ValueError("Dane są za krótkie dla formatu kaskadowego")
        
        # Parsuj nagłówek
        pos = 4
        
        aes_salt = encrypted_data[pos:pos + self.SALT_SIZE]
        pos += self.SALT_SIZE
        
        aes_nonce = encrypted_data[pos:pos + self.NONCE_SIZE]
        pos += self.NONCE_SIZE
        
        serpent_salt = encrypted_data[pos:pos + self.SALT_SIZE]
        pos += self.SALT_SIZE
        
        # Reszta to zaszyfrowane dane Serpent (zawierające IV + dane AES)
        serpent_encrypted = encrypted_data[pos:]
        
        # Krok 1: Odszyfrowanie Serpent-CBC
        serpent_key = self.generate_serpent_key(password, serpent_salt)
        try:
            # Deszyfruj Serpent (zwraca IV + padded AES data)
            decrypted_combined = serpent_cbc_decrypt(serpent_key, serpent_encrypted)
            
            # Wyciągnij IV i dane
            serpent_iv = decrypted_combined[:self.SERPENT_BLOCK_SIZE]
            padded_aes = decrypted_combined[self.SERPENT_BLOCK_SIZE:]
            
            # Usuń padding PKCS7
            aes_encrypted = self._unpad_pkcs7(padded_aes)
            
        except Exception as e:
            raise ValueError(f"Nieprawidłowe hasło lub uszkodzone dane (błąd Serpent): {e}")
        
        # Krok 2: Odszyfrowanie AES-GCM
        aes_key = self.generate_key(password, aes_salt)
        aesgcm = AESGCM(aes_key)
        
        try:
            decrypted_data = aesgcm.decrypt(aes_nonce, aes_encrypted, None)
        except Exception as e:
            raise ValueError(f"Nieprawidłowe hasło lub uszkodzone dane (błąd AES-GCM): {e}")
        
        return decrypted_data
    