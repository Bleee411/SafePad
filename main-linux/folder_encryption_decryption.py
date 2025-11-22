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

        # Sprawdź czy folder istnieje
        if not os.path.exists(folder_path):
            raise ValueError(f"Folder źródłowy nie istnieje: {folder_path}")
            
        # Sprawdź czy folder nie jest pusty
        if not any(os.scandir(folder_path)):
            raise ValueError(f"Folder źródłowy jest pusty: {folder_path}")

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
                        # Pomijanie ukrytych plików i tymczasowych
                        if os.path.basename(file_path).startswith('.'):
                            continue
                        arcname = os.path.relpath(file_path, folder_path)
                        all_files.append((file_path, arcname))
                
                total_files = len(all_files)
                if total_files == 0:
                    raise ValueError("Brak plików do zaszyfrowania w folderze")
                    
                for i, (file_path, arcname) in enumerate(all_files):
                    try:
                        zipf.write(file_path, arcname)
                        progress = (i + 1) / total_files * 50  # Kompresja to pierwsze 50%
                        update_progress(progress)
                        update_status(f"Kompresowanie... ({i+1}/{total_files})")
                    except Exception as e:
                        print(f"Ostrzeżenie: Nie udało się dodać pliku {file_path}: {e}")
                        continue
            
            update_status("Krok 2/3: Szyfrowanie danych...")
            
            # Sprawdź czy plik zip został utworzony i nie jest pusty
            if not os.path.exists(temp_zip_path) or os.path.getsize(temp_zip_path) == 0:
                raise ValueError("Nie udało się utworzyć archiwum ZIP")
            
            # Odczyt skompresowanych danych
            with open(temp_zip_path, 'rb') as f:
                zip_data = f.read()
            
            # Etap 2: Szyfrowanie (Ustawia postęp na 75%)
            update_progress(50)
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
            update_status("Szyfrowanie zakończone pomyślnie!")
            
            return True
            
        except Exception as e:
            # Usuń częściowo utworzony plik wyjściowy w przypadku błędu
            if os.path.exists(output_path):
                try:
                    os.remove(output_path)
                except:
                    pass
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

        # Sprawdź czy zaszyfrowany plik istnieje
        if not os.path.exists(encrypted_path):
            raise ValueError(f"Zaszyfrowany plik nie istnieje: {encrypted_path}")
            
        # Sprawdź czy folder wyjściowy istnieje, jeśli nie - utwórz
        if not os.path.exists(output_folder):
            os.makedirs(output_folder, exist_ok=True)
        elif not os.path.isdir(output_folder):
            raise ValueError(f"Ścieżka wyjściowa nie jest folderem: {output_folder}")

        temp_dir = tempfile.mkdtemp()
        temp_zip_path = os.path.join(temp_dir, "temp_folder.zip")
        
        try:
            update_status("Krok 1/3: Odczytywanie pliku...")
            
            # Etap 1: Odczyt i sprawdzenie
            with open(encrypted_path, 'rb') as f:
                file_data = f.read()
            
            if len(file_data) < 32:
                raise ValueError("Plik jest za krótki lub uszkodzony")
            
            version = file_data[:4].decode('utf-8', errors='ignore')
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
                
                if total_files == 0:
                    raise ValueError("Archiwum ZIP jest puste")
                
                for i, file_name in enumerate(file_list):
                    try:
                        # Bezpieczne wypakowywanie - zapobieganie atakom Path Traversal
                        safe_file_name = os.path.normpath(file_name)
                        if safe_file_name.startswith('..') or os.path.isabs(safe_file_name):
                            print(f"Ostrzeżenie: Pominięto podejrzaną ścieżkę: {file_name}")
                            continue
                            
                        zipf.extract(file_name, output_folder)
                        
                        # Dekompresja to drugie 50%
                        progress = 50 + (i + 1) / total_files * 50  
                        update_progress(progress)
                        update_status(f"Wypakowywanie... ({i+1}/{total_files})")
                    except Exception as e:
                        print(f"Ostrzeżenie: Nie udało się wypakować pliku {file_name}: {e}")
                        continue
                
            update_progress(100)
            update_status("Odszyfrowywanie zakończone pomyślnie!")
                
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
