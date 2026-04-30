import os
import zipfile
import tempfile
import shutil
from encryption_options import EncryptionHandler, ENCRYPTION_VERSION
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import struct

def secure_delete(path, passes=1):
    """Nadpisuje plik zerami przed usunięciem."""
    if not os.path.exists(path):
        return
    
    try:
        with open(path, "r+b") as f:
            length = os.path.getsize(path)
            for _ in range(passes):
                f.seek(0)
                f.write(b'\x00' * length)
                f.flush()
                os.fsync(f.fileno())
    except Exception as e:
        print(f"Błąd podczas bezpiecznego nadpisywania: {e}")
    finally:
        if os.path.exists(path):
            os.remove(path)

class FolderCrypto:
    def __init__(self, password, argon2_params):
        self.password = password
        self.encryption_handler = EncryptionHandler(argon2_params)
        self.CHUNK_SIZE = 50 * 1024 * 1024  #50 mb chunks

    def encrypt_folder(self, folder_path, output_path, progress_callback=None, status_callback=None):
        """Szyfruje folder strumieniowo"""
        
        def update_status(message):
            if status_callback:
                status_callback(message)
        
        def update_progress(value):
            if progress_callback:
                progress_callback(value)

        temp_dir = tempfile.mkdtemp()
        temp_zip_path = os.path.join(temp_dir, "temp_folder.zip")
        
        try:
            update_status("Krok 1/3: Pakowanie plików (bez kompresji)...")
            
            # Zbierz wszystkie pliki i oblicz całkowity rozmiar
            all_files = []
            total_size = 0
            
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_size = os.path.getsize(file_path)
                    total_size += file_size
                    arcname = os.path.relpath(file_path, folder_path)
                    all_files.append((file_path, arcname, file_size))
            
            processed_size = 0
            
            # zip bez kompresji
            with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_STORED) as zipf:
                for file_path, arcname, file_size in all_files:
                    zipf.write(file_path, arcname)
                    processed_size += file_size
                    if total_size > 0:
                        progress = (processed_size / total_size) * 30  # 30% na pakowanie
                        update_progress(progress)
            
            update_status("Krok 2/3: Szyfrowanie AES-GCM strumieniowo...")
            
            # Generuj klucz i nonce
            salt = os.urandom(self.encryption_handler.get_salt_size())
            nonce = os.urandom(self.encryption_handler.get_nonce_size())  # 12 bajtów dla GCM
            
            key = self.encryption_handler.generate_key(self.password, salt)
            
            # AES-GCM wymaga osobnego szyfrowania dla każdego chunka
            # Zapisz nagłówek z liczbą chunków
            zip_size = os.path.getsize(temp_zip_path)
            num_chunks = (zip_size + self.CHUNK_SIZE - 1) // self.CHUNK_SIZE
            
            with open(temp_zip_path, 'rb') as f_in:
                with open(output_path, 'wb') as f_out:
                    # Zapisz nagłówek
                    f_out.write(ENCRYPTION_VERSION.encode('utf-8'))
                    f_out.write(salt)
                    f_out.write(nonce)
                    f_out.write(struct.pack('>Q', num_chunks))  # liczba chunków
                    
                    processed_chunks = 0
                    chunk_nonce_counter = 0
                    
                    while True:
                        chunk = f_in.read(self.CHUNK_SIZE)
                        if not chunk:
                            break
                        
                        # Każdy chunk ma swój własny nonce (licznik + oryginalny nonce)
                        chunk_nonce = nonce + struct.pack('>I', chunk_nonce_counter)
                        chunk_nonce_counter += 1
                        
                        # Szyfruj pojedynczy chunk z AES-GCM
                        aesgcm = AESGCM(key)
                        encrypted_chunk = aesgcm.encrypt(chunk_nonce, chunk, None)
                        
                        # Zapisz długość zaszyfrowanego chunka + dane
                        f_out.write(struct.pack('>I', len(encrypted_chunk)))
                        f_out.write(encrypted_chunk)
                        
                        processed_chunks += 1
                        if num_chunks > 0:
                            progress = 30 + (processed_chunks / num_chunks) * 60
                            update_progress(progress)
            
            update_progress(100)
            update_status("Krok 3/3: Zakończono!")
            
            return True
            
        except Exception as e:
            raise e
        finally:
            # Czyszczenie
            try:
                if os.path.exists(temp_zip_path):
                    secure_delete(temp_zip_path)
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
            except:
                pass

    def decrypt_folder(self, encrypted_path, output_folder, progress_callback=None, status_callback=None):
        """Odszyfrowuje folder z AES-GCM strumieniowo."""
        
        def update_status(message):
            if status_callback:
                status_callback(message)
        
        def update_progress(value):
            if progress_callback:
                progress_callback(value)

        temp_dir = tempfile.mkdtemp()
        temp_zip_path = os.path.join(temp_dir, "temp_folder.zip")
        
        try:
            update_status("Krok 1/3: Odczytywanie nagłówka...")
            
            with open(encrypted_path, 'rb') as f_in:
                # Odczytaj nagłówek
                version = f_in.read(4).decode('utf-8')
                if version != ENCRYPTION_VERSION:
                    raise ValueError(f"Format pliku nie jest wspierany. Oczekiwano {ENCRYPTION_VERSION}, otrzymano {version}")
                
                salt = f_in.read(16)
                nonce = f_in.read(12)
                
                # Odczytaj liczbę chunków
                num_chunks_data = f_in.read(8)
                if len(num_chunks_data) < 8:
                    raise ValueError("Plik uszkodzony - brak danych o liczbie chunków")
                
                num_chunks = struct.unpack('>Q', num_chunks_data)[0]
                
                if len(salt) != 16 or len(nonce) != 12:
                    raise ValueError("Plik uszkodzony – nieprawidłowe dane nagłówka")
                
                key = self.encryption_handler.generate_key(self.password, salt)
                
                update_progress(10)
                update_status(f"Krok 2/3: Deszyfrowanie AES-GCM ({num_chunks} chunków)...")
                
                # Deszyfrowanie chunk po chunku
                with open(temp_zip_path, 'wb') as f_out:
                    for i in range(num_chunks):
                        # Odczytaj długość zaszyfrowanego chunka
                        chunk_len_data = f_in.read(4)
                        if len(chunk_len_data) < 4:
                            raise ValueError(f"Plik uszkodzony - brak danych o długości chunka {i}")
                        
                        chunk_len = struct.unpack('>I', chunk_len_data)[0]
                        
                        # Odczytaj zaszyfrowany chunk
                        encrypted_chunk = f_in.read(chunk_len)
                        if len(encrypted_chunk) < chunk_len:
                            raise ValueError(f"Plik uszkodzony - niepełny chunk {i}")
                        
                        # Odszyfruj chunk
                        chunk_nonce = nonce + struct.pack('>I', i)
                        aesgcm = AESGCM(key)
                        decrypted_chunk = aesgcm.decrypt(chunk_nonce, encrypted_chunk, None)
                        
                        f_out.write(decrypted_chunk)
                        
                        if num_chunks > 0:
                            progress = 10 + (i / num_chunks) * 40
                            update_progress(progress)
            
            if not zipfile.is_zipfile(temp_zip_path):
                raise ValueError("Odszyfrowane dane nie są prawidłowym plikiem ZIP")
            
            update_status("Krok 3/3: Wypakowywanie plików...")
            
            # Dekompresja z postępem
            with zipfile.ZipFile(temp_zip_path, 'r') as zipf:
                file_list = zipf.namelist()
                total_files = len(file_list)
                
                for i, file_name in enumerate(file_list):
                    # Zabezpieczenie przed path traversal
                    safe_path = os.path.normpath(os.path.join(output_folder, file_name))
                    if not safe_path.startswith(os.path.normpath(output_folder)):
                        raise ValueError("Path traversal detected in zip file")
                    
                    zipf.extract(file_name, output_folder)
                    progress = 50 + ((i + 1) / total_files) * 50
                    update_progress(progress)
            
            update_progress(100)
            update_status("Zakończono pomyślnie!")
            
            return True
            
        except Exception as e:
            raise e
        finally:
            try:
                if os.path.exists(temp_zip_path):
                    secure_delete(temp_zip_path)
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
            except:
                pass
