import os
import json
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import argon2
import winreg

# ------------------------------- Konfiguracja Parametrów Argona -------------------------------

class Registryconf:
    REG_PATH = r"Software\SafePad"
    
    DEFAULT_ARGON_PARAMS = {
        "low": {"m": 16 * 1024, "t": 2, "p": 1},
        "medium": {"m": 64 * 1024, "t": 3, "p": 2},
        "high": {"m": 512 * 1024, "t": 4, "p": 4}
    }
    
    @classmethod
    def save_argon_conf(cls, encryption_level, params):
        """Zapisuje parametry Argon2 dla danego poziomu"""
        try:
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, cls.REG_PATH)
            params_json = json.dumps(params)
            winreg.SetValueEx(key, f"argon_{encryption_level}", 0, winreg.REG_SZ, params_json)
            winreg.CloseKey(key)
            return True
        except Exception as e:
            print(f"Błąd zapisu Argon2: {e}")
            return False
    
    @classmethod
    def load_argon_conf(cls, encryption_level=None):
        """Ładuje parametry Argon2 z rejestru"""
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, cls.REG_PATH, 0, winreg.KEY_READ)
            
            if encryption_level is None:
                try:
                    encryption_level, _ = winreg.QueryValueEx(key, "encryption_level")
                except:
                    encryption_level = "medium"
            
            try:
                params_json, _ = winreg.QueryValueEx(key, f"argon_{encryption_level}")
                params = json.loads(params_json)
                winreg.CloseKey(key)
                return params
            except:
                winreg.CloseKey(key)
                return cls.DEFAULT_ARGON_PARAMS.get(encryption_level, cls.DEFAULT_ARGON_PARAMS["medium"])
            
        except FileNotFoundError:
            return cls.DEFAULT_ARGON_PARAMS.get(encryption_level, cls.DEFAULT_ARGON_PARAMS["medium"])
        except Exception as e:
            print(f"Błąd odczytu Argon2: {e}")
            return cls.DEFAULT_ARGON_PARAMS.get(encryption_level, cls.DEFAULT_ARGON_PARAMS["medium"])
    
    # ------------------------- NOWE METODY DO ZAPISU USTAWIEŃ -------------------------
    
    @classmethod
    def save_settings(cls, settings):
        """Zapisuje wszystkie ustawienia aplikacji w rejestrze"""
        try:
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, cls.REG_PATH)
            
            # Zapisz poziom szyfrowania
            winreg.SetValueEx(key, "encryption_level", 0, winreg.REG_SZ, settings.get("encryption_level", "medium"))
            
            # Zapisz wymagania hasła
            winreg.SetValueEx(key, "password_min_length", 0, winreg.REG_DWORD, settings.get("password_min_length", 8))
            winreg.SetValueEx(key, "password_require_upper", 0, winreg.REG_DWORD, 1 if settings.get("password_require_upper", True) else 0)
            winreg.SetValueEx(key, "password_require_lower", 0, winreg.REG_DWORD, 1 if settings.get("password_require_lower", True) else 0)
            winreg.SetValueEx(key, "password_require_number", 0, winreg.REG_DWORD, 1 if settings.get("password_require_number", True) else 0)
            winreg.SetValueEx(key, "password_require_special", 0, winreg.REG_DWORD, 1 if settings.get("password_require_special", False) else 0)
            
            # Zapisz ustawienia wyglądu
            winreg.SetValueEx(key, "dark_mode", 0, winreg.REG_DWORD, 1 if settings.get("dark_mode", True) else 0)
            winreg.SetValueEx(key, "notifications", 0, winreg.REG_DWORD, 1 if settings.get("notifications", True) else 0)
            
            
            winreg.CloseKey(key)
            return True
        except Exception as e:
            print(f"Błąd zapisu ustawień: {e}")
            return False
    
    @classmethod
    def load_settings(cls):
        """Ładuje wszystkie ustawienia aplikacji z rejestru"""
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
        
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, cls.REG_PATH, 0, winreg.KEY_READ)
            
            # Wczytaj poziom szyfrowania
            try:
                encryption_level, _ = winreg.QueryValueEx(key, "encryption_level")
                default_settings["encryption_level"] = encryption_level
            except:
                pass
            
            # Wczytaj wymagania hasła
            try:
                val, _ = winreg.QueryValueEx(key, "password_min_length")
                default_settings["password_min_length"] = val
            except:
                pass
            
            try:
                val, _ = winreg.QueryValueEx(key, "password_require_upper")
                default_settings["password_require_upper"] = bool(val)
            except:
                pass
            
            try:
                val, _ = winreg.QueryValueEx(key, "password_require_lower")
                default_settings["password_require_lower"] = bool(val)
            except:
                pass
            
            try:
                val, _ = winreg.QueryValueEx(key, "password_require_number")
                default_settings["password_require_number"] = bool(val)
            except:
                pass
            
            try:
                val, _ = winreg.QueryValueEx(key, "password_require_special")
                default_settings["password_require_special"] = bool(val)
            except:
                pass
            
            # Wczytaj ustawienia wyglądu
            try:
                val, _ = winreg.QueryValueEx(key, "dark_mode")
                default_settings["dark_mode"] = bool(val)
            except:
                pass
            
            try:
                val, _ = winreg.QueryValueEx(key, "notifications")
                default_settings["notifications"] = bool(val)
            except:
                pass
            
            try:
                val, _ = winreg.QueryValueEx(key, "minimize_to_tray")
                default_settings["minimize_to_tray"] = bool(val)
            except:
                pass
            
            
            winreg.CloseKey(key)
            
        except FileNotFoundError:
            # Jeśli rejestr nie istnieje, zapisz domyślne wartości
            cls.save_settings(default_settings)
        except Exception as e:
            print(f"Błąd odczytu ustawień: {e}")
        
        return default_settings
    
    @classmethod
    def save_stationary_pin(cls, pin):
        """Zapisuje PIN (hash) w rejestrze"""
        try:
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, cls.REG_PATH)
            import hashlib
            pin_hash = hashlib.sha256(pin.encode()).hexdigest()
            winreg.SetValueEx(key, "stationary_pin_hash", 0, winreg.REG_SZ, pin_hash)
            winreg.CloseKey(key)
            return True
        except Exception as e:
            print(f"Błąd zapisu PIN: {e}")
            return False
    
    @classmethod
    def check_stationary_pin(cls, pin):
        """Sprawdza czy PIN jest poprawny"""
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, cls.REG_PATH, 0, winreg.KEY_READ)
            stored_hash, _ = winreg.QueryValueEx(key, "stationary_pin_hash")
            winreg.CloseKey(key)
            
            import hashlib
            input_hash = hashlib.sha256(pin.encode()).hexdigest()
            return input_hash == stored_hash
        except:
            return False
    
    @classmethod
    def remove_stationary_pin(cls):
        """Usuwa PIN z rejestru"""
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, cls.REG_PATH, 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, "stationary_pin_hash")
            winreg.CloseKey(key)
            return True
        except:
            return False
        
        
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
                    
            

            

