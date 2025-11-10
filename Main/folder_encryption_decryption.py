import os
import zipfile
import tempfile
import shutil
from encryption_options import EncryptionHandler, ENCRYPTION_VERSION
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

class FolderCrypto:
    def __init__(self, password, argon2_params):
        self.password = password
        self.encryption_handler = EncryptionHandler(argon2_params)

    def encrypt_folder(self, folder_path, output_path, progress_callback=None, status_callback=None):
        """Szyfruje folder i zapisuje do pliku wyjściowego z lepszym raportowaniem postępu."""
        
        # Funkcje pomocnicze do aktualizacji UI
        def update_status(message):
            if status_callback:
                status_callback(message)
        
        def update_progress(value):
            if progress_callback:
                progress_callback(value)

        temp_dir = tempfile.mkdtemp()
        temp_zip_path = os.path.join(temp_dir, "temp_folder.zip")
        
        try:
            update_status("Krok 1/3: Kompresowanie plików...")
            
            # Etap 1: Kompresja (0% -> 50% postępu)
            with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                all_files = []
                for root, dirs, files in os.walk(folder_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, folder_path)
                        all_files.append((file_path, arcname))
                
                total_files = len(all_files)
                for i, (file_path, arcname) in enumerate(all_files):
                    zipf.write(file_path, arcname)
                    progress = (i + 1) / total_files * 50  # Kompresja to pierwsze 50%
                    update_progress(progress)
            
            update_status("Krok 2/3: Szyfrowanie danych...")
            
            # Odczyt skompresowanych danych
            with open(temp_zip_path, 'rb') as f:
                zip_data = f.read()
            
            # Etap 2: Szyfrowanie (Ustawia postęp na 75%)
            # To jest pojedyncza, wolna operacja, więc po prostu ustawiamy postęp
            salt = os.urandom(self.encryption_handler.get_salt_size())
            nonce = os.urandom(self.encryption_handler.get_nonce_size())
            key = self.encryption_handler.generate_key(self.password, salt)
            encrypted_data = self.encryption_handler.encrypt_data(key, nonce, zip_data)
            update_progress(75)
            
            update_status("Krok 3/3: Zapisywanie pliku...")
            
            # Etap 3: Zapis (Ustawia postęp na 100%)
            with open(output_path, 'wb') as f:
                f.write(ENCRYPTION_VERSION.encode('utf-8'))
                f.write(salt)
                f.write(nonce)
                f.write(encrypted_data)
                
            update_progress(100)
            
            return True
            
        except Exception as e:
            raise e
        finally:
            # Czyszczenie
            try:
                if os.path.exists(temp_zip_path):
                    os.unlink(temp_zip_path)
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
            except:
                pass

    def decrypt_folder(self, encrypted_path, output_folder, progress_callback=None, status_callback=None):
        """Odszyfrowuje folder z lepszym raportowaniem postępu."""
        
        # Funkcje pomocnicze
        def update_status(message):
            if status_callback:
                status_callback(message)
        
        def update_progress(value):
            if progress_callback:
                progress_callback(value)

        temp_dir = tempfile.mkdtemp()
        temp_zip_path = os.path.join(temp_dir, "temp_folder.zip")
        
        try:
            update_status("Krok 1/3: Odczytywanie pliku...")
            
            # Etap 1: Odczyt i sprawdzenie
            with open(encrypted_path, 'rb') as f:
                file_data = f.read()
            
            if len(file_data) < 32:
                raise ValueError("Plik jest za krótki lub uszkodzony")
            
            version = file_data[:4].decode('utf-8')
            if version != ENCRYPTION_VERSION:
                 raise ValueError("Format pliku nie jest wspierany")
            
            update_progress(10) # Mały postęp za odczyt

            # Etap 2: Deszyfrowanie (Ustawia postęp na 50%)
            update_status("Krok 2/3: Deszyfrowanie danych...")
            salt = file_data[4:20]
            nonce = file_data[20:32]
            encrypted_data = file_data[32:]
            
            key = self.encryption_handler.generate_key(self.password, salt)
            decrypted_data = self.encryption_handler.decrypt_data(key, nonce, encrypted_data)
            update_progress(50)
            
            # Zapis odszyfrowanych danych do tymczasowego zipa
            with open(temp_zip_path, 'wb') as f:
                f.write(decrypted_data)
            
            if not zipfile.is_zipfile(temp_zip_path):
                raise ValueError("Odszyfrowane dane nie są prawidłowym plikiem ZIP")
            
            # Etap 3: Dekompresja (50% -> 100% postępu)
            update_status("Krok 3/3: Wypakowywanie plików...")
            with zipfile.ZipFile(temp_zip_path, 'r') as zipf:
                file_list = zipf.namelist()
                total_files = len(file_list)
                
                for i, file_name in enumerate(file_list):
                    zipf.extract(file_name, output_folder)
                    
                    # Dekompresja to drugie 50%
                    progress = 50 + (i + 1) / total_files * 50  
                    update_progress(progress)
                
            update_progress(100)
                
            return True
            
        except Exception as e:
            raise e
        finally:
            # Czyszczenie
            try:
                if os.path.exists(temp_zip_path):
                    os.unlink(temp_zip_path)
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
            except:
                pass