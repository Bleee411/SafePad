import os
import json
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import argon2
from pathlib import Path

# ------------------------------- Konfiguracja Parametrów Argona -------------------------------

class Registryconf:
    # Używamy XDG_CONFIG_HOME zgodnie ze standardem Linux
    CONFIG_DIR = Path.home() / ".config" / "SafePad"
    CONFIG_FILE = CONFIG_DIR / "settings.json"
    ARGON_CONFIG_FILE = CONFIG_DIR / "argon_config.json"
    
    DEFAULT_ARGON_PARAMS = {
        "low": {"m": 16 * 1024, "t": 2, "p": 1},
        "medium": {"m": 64 * 1024, "t": 3, "p": 2},
        "high": {"m": 512 * 1024, "t": 4, "p": 4}
    }
    
    @classmethod
    def _ensure_config_dir(cls):
        """Tworzy katalog konfiguracyjny, jeśli nie istnieje."""
        cls.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    
    @classmethod
    def _read_config(cls, filepath):
        """Odczytuje plik JSON lub zwraca pusty słownik."""
        try:
            if filepath.exists():
                with open(filepath, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except (json.JSONDecodeError, Exception) as e:
            print(f"Błąd odczytu pliku konfiguracyjnego {filepath}: {e}")
        return {}
    
    @classmethod
    def _write_config(cls, filepath, data):
        """Zapisuje dane do pliku JSON."""
        cls._ensure_config_dir()
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4)
            return True
        except Exception as e:
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
        """Zapisuje wszystkie ustawienia aplikacji w pliku JSON."""
        return cls._write_config(cls.CONFIG_FILE, settings)
    
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
    def save_stationary_pin(cls, pin):
        """Zapisuje PIN (hash) w pliku konfiguracyjnym."""
        settings = cls._read_config(cls.CONFIG_FILE)
        import hashlib
        pin_hash = hashlib.sha256(pin.encode()).hexdigest()
        settings["stationary_pin_hash"] = pin_hash
        return cls._write_config(cls.CONFIG_FILE, settings)
    
    @classmethod
    def check_stationary_pin(cls, pin):
        """Sprawdza czy PIN jest poprawny."""
        settings = cls._read_config(cls.CONFIG_FILE)
        stored_hash = settings.get("stationary_pin_hash")
        if not stored_hash:
            return False
        
        import hashlib
        input_hash = hashlib.sha256(pin.encode()).hexdigest()
        return input_hash == stored_hash
    
    @classmethod
    def remove_stationary_pin(cls):
        """Usuwa PIN z pliku konfiguracyjnego."""
        settings = cls._read_config(cls.CONFIG_FILE)
        if "stationary_pin_hash" in settings:
            del settings["stationary_pin_hash"]
        return cls._write_config(cls.CONFIG_FILE, settings)

    @classmethod
    def get_current_level(cls):
        """Pobiera obecny poziom szyfrowania z głównych ustawień."""
        settings = cls._read_config(cls.CONFIG_FILE)
        return settings.get("encryption_level", "medium")
    
    
    @classmethod
    def save_backup_password(cls, password):
        """Zapisuje własne hasło do backupów sesji."""
        settings = cls._read_config(cls.CONFIG_FILE)
        import base64
        # Kodowanie base64 dla podstawowego zabezpieczenia (nie jest to silne szyfrowanie)
        encoded_password = base64.b64encode(password.encode('utf-8')).decode('utf-8')
        settings["backup_password"] = encoded_password
        return cls._write_config(cls.CONFIG_FILE, settings)
    
    @classmethod
    def load_backup_password(cls):
        """Wczytuje własne hasło do backupów sesji."""
        settings = cls._read_config(cls.CONFIG_FILE)
        encoded_password = settings.get("backup_password")
        if encoded_password:
            import base64
            try:
                return base64.b64decode(encoded_password.encode('utf-8')).decode('utf-8')
            except Exception as e:
                print(f"Błąd dekodowania hasła backupu: {e}")
                return None
        return None
    
    @classmethod
    def delete_backup_password(cls):
        """Usuwa własne hasło do backupów (przywraca domyślne)."""
        settings = cls._read_config(cls.CONFIG_FILE)
        if "backup_password" in settings:
            del settings["backup_password"]
        return cls._write_config(cls.CONFIG_FILE, settings)

        
        
#------------------------------- Szyfrowanie -------------------------------


class EncryptionCEO:
    
    ENCRYPTION_VERSION = "V2.0"
    SALT_SIZE = 16
    NONCE_SIZE = 12 #96 bitów dla GCM
    
    def __init__(self, encryption_level=None):
        self.encryption_level = encryption_level or Registryconf.get_current_level()
        self.argon_params = Registryconf.load_argon_conf(self.encryption_level)
        
    def generate_key(self, password, salt):
        try:
            key = argon2.low_level.hash_secret_raw(
                secret=password.encode('utf-8'),
                salt=salt,
                time_cost=self.argon_params['t'],
                memory_cost=self.argon_params['m'],
                parallelism=self.argon_params['p'],
                hash_len=32, #256 bitów dla aes gcm
                type=argon2.low_level.Type.ID
            )
            return key
        except Exception as e:
            print(f"Błąd generowania klucza: {e}")
            raise
        
        
    def encrypt_data(self, password, data):
        
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
    
    def decrypt_data(self, password, encrypted_data):
        
        #sprawdź minimalną długość 
        
        header_size = 4 + self.SALT_SIZE + self.NONCE_SIZE
        if len(encrypted_data) < header_size:
            raise ValueError("Dane są za krótkie albo uszkodzone")
        
        #sprawdź wersję szyfrowania
        
        version = encrypted_data[:4].decode('utf-8')
        if version != self.ENCRYPTION_VERSION:
            raise ValueError(f"Nieobsługiwana wersja szyfrowania: {version}")
        
        #odczytaj salt i nonce
        
        salt = encrypted_data[4:4 + self.SALT_SIZE]
        nonce = encrypted_data[4 + self.SALT_SIZE:header_size]
        ciphertext = encrypted_data[header_size:]
        
        #generuj klucz
        key = self.generate_key(password, salt)
        
        #odszyfruj
        
        aesgcm = AESGCM(key)
        decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
        
        return decrypted_data
    
    def encrypt_file(self, password, input_path, output_path, progress_callback=None):
        try:
            with open(input_path, 'rb') as f:
                data = f.read()
                
            if progress_callback:
                progress_callback(50)
                
            encrypted = self.encrypt_data(password, data)
            
            if progress_callback:
                progress_callback(100)
                
            #zapisz 
            
            with open (output_path, 'wb') as f:
                f.write(encrypted)
                
            return True
        except Exception as e:
            raise Exception(f"Błąd szyfrowania pliku: {e}")
        
    def decrypt_file(self, password, input_path, output_path, progress_callback=None):
        try:
            #odczytaj plik
            
            with open (input_path, 'rb') as f:
                encrypted_data = f.read()
                
            if progress_callback:
                progress_callback(50)
                
            decrypted = self.decrypt_data(password, encrypted_data)
            
            if progress_callback:
                progress_callback(100)
                
            #zapisz
            
            with open (output_path, 'wb') as f:
                f.write(decrypted)
                
            return True
        except Exception as e:
            raise Exception(f"Błąd odszyfrowywania pliku: {e}")
        
        
    def encrypt_data_chunked(self, password, input_path, output_path, chunk_size=50*1024*1024, progress_callback=None):
        try:
            file_size = os.path.getsize(input_path)
            num_chunks = (file_size + chunk_size - 1) // chunk_size
            
            #generuj sól i nonce
            
            salt = os.urandom(self.SALT_SIZE)
            nonce_base = os.urandom(self.NONCE_SIZE)
            key = self.generate_key(password, salt)
            
            with open(input_path, 'rb') as f_in:
                with open(output_path, 'wb') as f_out:
                    #zapisz nagłówek
                    f_out.write(self.ENCRYPTION_VERSION.encode('utf-8'))
                    f_out.write(salt)
                    f_out.write(nonce_base)
                    f_out.write(num_chunks.to_bytes(8, byteorder='big'))
                    
                    procced = 0
                    aesgcm = AESGCM(key)
                    
                    for chunk_idx in range(num_chunks):
                        chunk = f_in.read(chunk_size)
                        if not chunk:
                            break
                        
                        #unikalny nonce dla każdego chunka
                        
                        nonce = nonce_base + chunk_idx.to_bytes(4, byteorder='big')
                        
                        #szyfruj chunk
                        
                        encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)
                        
                        #zapisz długość i dane
                        f_out.write(len(encrypted_chunk).to_bytes(4, byteorder='big'))
                        f_out.write(encrypted_chunk)
                        
                        procced += len(chunk)
                        if progress_callback and file_size > 0:
                            progress_callback(int(procced / file_size * 100))
                            
            return True
        except Exception as e:
            raise Exception(f"Błąd szyfrowania pliku: {e}")
                    
            

            

