import os
import json
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pyserpent import serpent_cbc_encrypt, serpent_cbc_decrypt
from cryptography.hazmat.primitives import hashes
import argon2
import winreg
import base64
import ctypes
from ctypes import wintypes


# ------------------------------- Ochrona sekretów przez Windows DPAPI -------------------------------
# Base64 nie jest szyfrowaniem - jest trywialnie odwracalny przez każdego, kto ma
# dostęp do rejestru. Zamiast tego korzystamy z Windows DPAPI (CryptProtectData /
# CryptUnprotectData), które szyfruje dane kluczem powiązanym z kontem
# zalogowanego użytkownika Windows - inny użytkownik/proces nie odczyta sekretu
# nawet mając pełny odczyt rejestru bieżącego użytkownika.

class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _to_blob(data: bytes) -> _DATA_BLOB:
    buf = ctypes.create_string_buffer(data, len(data))
    return _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))


def dpapi_protect(data: bytes) -> bytes:
    """Szyfruje dane za pomocą Windows DPAPI (powiązane z bieżącym użytkownikiem)."""
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    in_blob = _to_blob(data)
    out_blob = _DATA_BLOB()

    ok = crypt32.CryptProtectData(
        ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)
    )
    if not ok:
        raise OSError("CryptProtectData nie powiodło się")

    try:
        result = ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)

    return result


def dpapi_unprotect(data: bytes) -> bytes:
    """Odszyfrowuje dane zapisane przez dpapi_protect()."""
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    in_blob = _to_blob(data)
    out_blob = _DATA_BLOB()

    ok = crypt32.CryptUnprotectData(
        ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)
    )
    if not ok:
        raise OSError("CryptUnprotectData nie powiodło się (inny użytkownik/komputer?)")

    try:
        result = ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)

    return result


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
    
    # ------------------------- Zapisz ustawień -------------------------
    
    @classmethod
    def save_settings(cls, settings):
        """Zapisuje wszystkie ustawienia aplikacji do rejestru"""
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

            # HOTFIX: brakujący zapis minimize_to_tray - był odczytywany w
            # load_settings(), ale nigdy nie zapisywany, przez co ustawienie
            # nie przetrwało restartu aplikacji.
            winreg.SetValueEx(key, "minimize_to_tray", 0, winreg.REG_DWORD, 1 if settings.get("minimize_to_tray", False) else 0)
            
            
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
            "minimize_to_tray": False,
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
    
    @staticmethod
    def save_backup_password(password):
        try:
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, Registryconf.REG_PATH)
            # Chronimy hasło przez Windows DPAPI (powiązane z kontem użytkownika),
            # a nie samym base64, który jest trywialnie odwracalny.
            protected = dpapi_protect(password.encode('utf-8'))
            encoded_password = base64.b64encode(protected).decode()
            winreg.SetValueEx(key, "BackupPassword", 0, winreg.REG_SZ, encoded_password)
            winreg.CloseKey(key)
            return True
        except Exception as e:
            print(f"Nie można zapisać hasła do backupów: {e}")
            return False
    
    @staticmethod
    def load_backup_password():
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, Registryconf.REG_PATH, 0, winreg.KEY_READ)
            try:
                encoded_password, _ = winreg.QueryValueEx(key, "BackupPassword")
                protected = base64.b64decode(encoded_password)
                password = dpapi_unprotect(protected).decode('utf-8')
                winreg.CloseKey(key)
                return password
            except FileNotFoundError:
                winreg.CloseKey(key)
                return None
        except Exception as e:
            print(f"Nie można wczytać hasła do backupów: {e}")
            return None
    
    @staticmethod
    def delete_backup_password():
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, Registryconf.REG_PATH, 0, winreg.KEY_SET_VALUE)
            try:
                winreg.DeleteValue(key, "BackupPassword")
            except FileNotFoundError:
                pass
            winreg.CloseKey(key)
            return True
        except Exception as e:
            print(f"Nie można usunąć hasła do backupów: {e}")
            return False

        
        
#------------------------------- Szyfrowanie -------------------------------


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
        """
        Generuje osobny klucz dla Serpent (256 bit).

        UWAGA: `salt` przekazywany tutaj (serpent_salt) jest już od początku
        generowany niezależnym wywołaniem os.urandom(), oddzielnym od
        aes_salt użytego w generate_key(). Poniższe XOR z 0xAA nie dodaje
        więc żadnej realnej separacji kryptograficznej ponad to, co daje
        sama niezależna losowość salta - jest nieszkodliwe, ale zbędne.
        CELOWO NIE usuwamy/zmieniamy tej transformacji: zmiana sposobu
        wyprowadzania klucza złamałaby kompatybilność wsteczną i
        uniemożliwiła odszyfrowanie plików zaszyfrowanych wcześniejszymi
        wersjami aplikacji.
        """
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
    def _unpad_pkcs7(padded_data, block_size=16):
        """Usuwa padding PKCS7.

        Weryfikuje WSZYSTKIE bajty paddingu (nie tylko ostatni) w czasie
        stałym (hmac.compare_digest), żeby nie dawać atakującemu żadnej
        dodatkowej informacji o tym, w którym miejscu padding jest
        nieprawidłowy (ochrona przed atakiem typu padding oracle)."""
        if len(padded_data) < block_size or len(padded_data) % block_size != 0:
            raise ValueError("Nieprawidłowy padding")

        padding_length = padded_data[-1]
        if padding_length < 1 or padding_length > block_size:
            raise ValueError("Nieprawidłowy padding")

        expected = bytes([padding_length]) * padding_length
        actual = padded_data[-padding_length:]
        if not hmac.compare_digest(actual, expected):
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
        
        try:
            key = self.generate_key(password, salt)
            aesgcm = AESGCM(key)
            decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception:
            raise ValueError("Nieprawidłowe hasło lub uszkodzone dane")

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
        
        # UWAGA - ochrona przed atakiem typu padding oracle:
        # Poniższe dwa etapy (deszyfrowanie/unpad Serpent-CBC oraz weryfikacja
        # tagu AES-GCM) CELOWO zgłaszają identyczny, ogólny komunikat błędu.
        # Wcześniej każdy etap miał inny tekst błędu ("błąd Serpent" vs
        # "błąd AES-GCM"), co pozwalało atakującemu - przez obserwację, który
        # komunikat się pojawia dla spreparowanych danych - odróżnić błąd
        # paddingu CBC od błędu autentykacji GCM. To klasyczny warunek do
        # ataku Vaudenay'a (CBC padding oracle), niezależny od siły hasła.
        # Nie zmieniaj poniższego zachowania bez zachowania jednego,
        # nieodróżnialnego komunikatu błędu dla obu etapów.
        generic_error = "Nieprawidłowe hasło lub uszkodzone dane"

        # Krok 1: Odszyfrowanie Serpent-CBC
        try:
            serpent_key = self.generate_serpent_key(password, serpent_salt)
            # Deszyfruj Serpent (zwraca IV + padded AES data)
            decrypted_combined = serpent_cbc_decrypt(serpent_key, serpent_encrypted)

            # Wyciągnij IV i dane
            padded_aes = decrypted_combined[self.SERPENT_BLOCK_SIZE:]

            # Usuń padding PKCS7 (walidacja pełnego paddingu w czasie stałym)
            aes_encrypted = self._unpad_pkcs7(padded_aes)
        except Exception:
            raise ValueError(generic_error)

        # Krok 2: Odszyfrowanie AES-GCM
        try:
            aes_key = self.generate_key(password, aes_salt)
            aesgcm = AESGCM(aes_key)
            decrypted_data = aesgcm.decrypt(aes_nonce, aes_encrypted, None)
        except Exception:
            raise ValueError(generic_error)

        return decrypted_data
    
    # NOTE: tutaj istniał martwy kod run_argon2_benchmark, który został usunięty, ponieważ nie był wywoływany i nie był powiązany z żadną klasą. Logika benchmarku Argon2ID została przeniesiona do ui.py (SettingsDialog.run_benchmark / BenchmarkThread).