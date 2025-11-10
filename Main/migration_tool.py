import os
import shutil
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, simpledialog
from threading import Thread
from encryption_options import EncryptionHandler, ENCRYPTION_VERSION
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

class MigrationTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Narzędzie Migracji SafePad")
        self.root.geometry("600x400")
        
        default_params = {"m": 64 * 1024, "t": 3, "p": 2}
        self.new_encryption_handler = EncryptionHandler(default_params) 
        
        self.setup_ui()
        
    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill="both", expand=True)
        
        title_label = ttk.Label(main_frame, 
                              text="Narzędzie Migracji SafePad", 
                              font=("Arial", 16, "bold"))
        title_label.pack(pady=10)
        
        desc_label = ttk.Label(main_frame, 
                             text="To narzędzie konwertuje stare pliki (.sscr sprzed wersji 2.0) do nowego, bezpieczniejszego formatu (z Argon2 i AES-GCM).",
                             wraplength=550)
        desc_label.pack(pady=10)
        
        folder_frame = ttk.Frame(main_frame)
        folder_frame.pack(fill="x", pady=10)
        
        ttk.Label(folder_frame, text="Wybierz folder:").pack(anchor="w")
        
        self.folder_path = tk.StringVar()
        folder_entry = ttk.Entry(folder_frame, textvariable=self.folder_path, width=50, state="readonly")
        folder_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        
        browse_btn = ttk.Button(folder_frame, text="Przeglądaj...", command=self.browse_folder)
        browse_btn.pack(side="right")
        
        options_frame = ttk.LabelFrame(main_frame, text="Opcje migracji", padding="10")
        options_frame.pack(fill="x", pady=10)
        
        self.backup_files = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame,
                       text="Stwórz backup starych plików (zmieni nazwę na *.old.bak)",
                       variable=self.backup_files).pack(anchor="w")
        
        progress_frame = ttk.Frame(main_frame)
        progress_frame.pack(fill="x", pady=10)
        
        self.progress_var = tk.DoubleVar()
        progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100)
        progress_bar.pack(fill="x")
        
        self.status_label = ttk.Label(progress_frame, text="Gotowy")
        self.status_label.pack(anchor="w", pady=(5, 0))
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(side="bottom", fill="x", pady=10)
        
        start_btn = ttk.Button(button_frame, text="Rozpocznij migrację", command=self.start_migration)
        start_btn.pack(side="right", padx=5)
        
        cancel_btn = ttk.Button(button_frame, text="Zamknij", command=self.root.destroy)
        cancel_btn.pack(side="right", padx=5)
        
    def browse_folder(self):
        folder = filedialog.askdirectory(title="Wybierz folder zawierający pliki .sscr")
        if folder:
            self.folder_path.set(folder)
            
    def start_migration(self):
        folder = self.folder_path.get()
        if not folder or not os.path.isdir(folder):
            messagebox.showerror("Błąd", "Wybierz prawidłowy folder.", parent=self.root)
            return
        
        password = simpledialog.askstring("Wymagane hasło", 
                                          "Podaj hasło do starych plików:", 
                                          show='*', parent=self.root)
        if not password:
            messagebox.showwarning("Anulowano", "Migracja anulowana. Nie podano hasła.", parent=self.root)
            return
            
        Thread(target=self.migrate_files, args=(folder, password), daemon=True).start()
        
    def decrypt_legacy(self, file_data, password):
        """Deszyfruje dane w starym formacie (AES-CBC + PBKDF2)."""
        try:
            salt = file_data[:16]
            iv = file_data[16:32]
            encrypted_data = file_data[32:]
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(password.encode())
            
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
            
            unpadder = PKCS7(128).unpadder()
            decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()
            
            return decrypted_data
        except Exception as e:
            print(f"Błąd deszyfrowania legacy: {e}")
            return None 

    def encrypt_new(self, data, password):
        """Szyfruje dane do nowego formatu (AES-GCM + Argon2)."""
        try:
            salt = os.urandom(self.new_encryption_handler.get_salt_size())
            nonce = os.urandom(self.new_encryption_handler.get_nonce_size())
            
            key = self.new_encryption_handler.generate_key(password, salt)
            encrypted_data = self.new_encryption_handler.encrypt_data(key, nonce, data)
            
            return (ENCRYPTION_VERSION.encode('utf-8') + salt + nonce + encrypted_data)
        except Exception as e:
            print(f"Błąd szyfrowania new: {e}")
            return None

    def migrate_files(self, folder_path, password):
        safepad_files = []
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                if file.endswith('.sscr'):
                    safepad_files.append(os.path.join(root, file))
        
        total_files = len(safepad_files)
        if total_files == 0:
            self.update_status("Nie znaleziono plików .sscr w tym folderze.")
            return
            
        migrated_count = 0
        error_count = 0
        skipped_count = 0
        
        for i, file_path in enumerate(safepad_files):
            try:
                self.update_progress((i / total_files) * 100)
                self.update_status(f"Przetwarzanie {i+1}/{total_files}: {os.path.basename(file_path)}")
                
                with open(file_path, "rb") as f:
                    file_data = f.read()
                
                if file_data.startswith(ENCRYPTION_VERSION.encode('utf-8')):
                    skipped_count += 1
                    continue
                
                decrypted_data = self.decrypt_legacy(file_data, password)
                
                if decrypted_data is None:
                    raise ValueError("Nieprawidłowe hasło lub uszkodzony plik (legacy)")

                new_file_data = self.encrypt_new(decrypted_data, password)
                
                if new_file_data is None:
                    raise ValueError("Nie udało się zaszyfrować pliku do nowego formatu")
                
                if self.backup_files.get():
                    backup_path = file_path + ".old.bak"
                    shutil.move(file_path, backup_path) 
                
                with open(file_path, "wb") as f:
                    f.write(new_file_data)
                
                migrated_count += 1
                
            except Exception as e:
                error_count += 1
                self.update_status(f"Błąd migracji {os.path.basename(file_path)}: {e}")
                
        self.update_progress(100)
        summary_message = f"Migracja zakończona. \n\nZmigrowano: {migrated_count}\nPominięto (nowy format): {skipped_count}\nBłędy: {error_count}"
        self.update_status(summary_message)
        
        if error_count == 0:
            messagebox.showinfo("Sukces", summary_message, parent=self.root)
        else:
            messagebox.showwarning("Ukończono z błędami", summary_message, parent=self.root)
    
    def update_progress(self, value):
        self.root.after(0, lambda: self.progress_var.set(value))
    
    def update_status(self, message):
        self.root.after(0, lambda: self.status_label.config(text=message))

def main():
    root = tk.Tk()
    app = MigrationTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()