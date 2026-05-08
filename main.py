"""
SafePad
Autor: Szofer
Licencja: MIT
Wersja: 2.2.0_BETA.1
"""

import sys
import os
import tempfile
import shutil
import zipfile
from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtWidgets import (QApplication, QMessageBox, QFileDialog, QInputDialog, 
                             QProgressDialog, QLineEdit, QDialog, QPushButton)
from PyQt6.QtGui import QIcon
import ctypes

from gui.ui import SafePadGUI
from crypto.encryption_decryption import EncryptionCEO, Registryconf
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pyserpent import serpent_cbc_encrypt, serpent_cbc_decrypt
from others.others import Argon2Benchmark, is_benchmark_needed

ctypes.windll.shell32.SHChangeNotify(0x08000000, 0x0000, None, None) 

APP_VERSION = "2.2.0_BETA.1"
AUTHOR = "Szofer"

DEFAULT_BACKUP_PASSWORD = "U2FsdGVkX187GOHqhIryMT+tJgiOcwSNH6UkWAw80Y37xpUsp40tC/+59LY6DIqm7G8+9y+44PIfqmVl8lnb72rhmZKN/UWN7J1JMPXlJ8I="


class FolderEncryptWorker(QThread):
    progress = pyqtSignal(int)
    status = pyqtSignal(str)
    finished = pyqtSignal(str)
    error = pyqtSignal(str)
    
    def __init__(self, crypto, password, folder_path, output_path):
        super().__init__()
        self.crypto = crypto
        self.password = password
        self.folder_path = folder_path
        self.output_path = output_path
        self.CHUNK_SIZE = 50 * 1024 * 1024
    
    def run(self):
      try:
        self.status.emit("Pakowanie plików...")
        
        temp_dir = tempfile.mkdtemp()
        temp_zip = os.path.join(temp_dir, "temp_folder.zip")
        
        all_files = []
        total_size = 0
        for root, dirs, files in os.walk(self.folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                file_size = os.path.getsize(file_path)
                total_size += file_size
                arcname = os.path.relpath(file_path, self.folder_path)
                all_files.append((file_path, arcname, file_size))
        
        if not all_files:
            raise Exception("Folder jest pusty!")
        
        processed_size = 0
        with zipfile.ZipFile(temp_zip, 'w', zipfile.ZIP_STORED) as zipf:
            for file_path, arcname, file_size in all_files:
                zipf.write(file_path, arcname)
                processed_size += file_size
                if total_size > 0:
                    self.progress.emit(int((processed_size / total_size) * 30))
        
        self.status.emit("Szyfrowanie danych...")
        
        file_size = os.path.getsize(temp_zip)
        num_chunks = (file_size + self.CHUNK_SIZE - 1) // self.CHUNK_SIZE
        
        if self.crypto.use_cascade:
            # ===== SZYFROWANIE KASKADOWE AES-GCM + SERPENT-CBC =====
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            from pyserpent import serpent_cbc_encrypt
            
            # Generuj klucze i parametry dla AES
            aes_salt = os.urandom(self.crypto.SALT_SIZE)
            aes_nonce_base = os.urandom(self.crypto.NONCE_SIZE)
            aes_key = self.crypto.generate_key(self.password, aes_salt)
            
            # Generuj klucze i parametry dla Serpent (inne!)
            serpent_salt = os.urandom(self.crypto.SALT_SIZE)
            serpent_key = self.crypto.generate_serpent_key(self.password, serpent_salt)
            
            with open(temp_zip, 'rb') as f_in:
                with open(self.output_path, 'wb') as f_out:
                    # Nagłówek kaskadowy V3.0
                    f_out.write(self.crypto.CASCADE_VERSION.encode('utf-8'))
                    f_out.write(aes_salt)           # 16 bajtów
                    f_out.write(aes_nonce_base)     # 12 bajtów
                    f_out.write(serpent_salt)       # 16 bajtów
                    f_out.write(num_chunks.to_bytes(8, 'big'))
                    
                    aesgcm = AESGCM(aes_key)
                    
                    processed = 0
                    for chunk_idx in range(num_chunks):
                        chunk = f_in.read(self.CHUNK_SIZE)
                        if not chunk:
                            break
                        
                        # Krok 1: Szyfrowanie AES-GCM
                        aes_nonce = aes_nonce_base + chunk_idx.to_bytes(4, 'big')
                        aes_encrypted = aesgcm.encrypt(aes_nonce, chunk, None)
                        
                        # Krok 2: Przygotowanie do Serpent (IV + padding + dane)
                        chunk_iv = os.urandom(self.crypto.SERPENT_BLOCK_SIZE)  # Unikalne IV dla każdego chunka
                        padded_data = self.crypto._pad_pkcs7(aes_encrypted, self.crypto.SERPENT_BLOCK_SIZE)
                        combined_data = chunk_iv + padded_data  # IV + dane
                        
                        # Krok 3: Szyfrowanie Serpent-CBC
                        serpent_encrypted = serpent_cbc_encrypt(serpent_key, combined_data)
                        
                        # Zapisz chunk
                        f_out.write(len(serpent_encrypted).to_bytes(4, 'big'))
                        f_out.write(serpent_encrypted)
                        
                        processed += len(chunk)
                        if file_size > 0:
                            self.progress.emit(30 + int((processed / file_size) * 60))
        else:
            # ===== STANDARDOWE SZYFROWANIE AES-GCM =====
            salt = os.urandom(self.crypto.SALT_SIZE)
            nonce_base = os.urandom(self.crypto.NONCE_SIZE)
            key = self.crypto.generate_key(self.password, salt)
            
            with open(temp_zip, 'rb') as f_in:
                with open(self.output_path, 'wb') as f_out:
                    f_out.write(self.crypto.ENCRYPTION_VERSION.encode('utf-8'))
                    f_out.write(salt)
                    f_out.write(nonce_base)
                    f_out.write(num_chunks.to_bytes(8, 'big'))
                    
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                    aesgcm = AESGCM(key)
                    
                    processed = 0
                    for chunk_idx in range(num_chunks):
                        chunk = f_in.read(self.CHUNK_SIZE)
                        if not chunk:
                            break
                        
                        nonce = nonce_base + chunk_idx.to_bytes(4, 'big')
                        encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)
                        
                        f_out.write(len(encrypted_chunk).to_bytes(4, 'big'))
                        f_out.write(encrypted_chunk)
                        
                        processed += len(chunk)
                        if file_size > 0:
                            self.progress.emit(30 + int((processed / file_size) * 60))
        
        # Bezpieczne usunięcie pliku tymczasowego ZIP
        self._secure_delete(temp_zip)
        shutil.rmtree(temp_dir, ignore_errors=True)
        
        self.progress.emit(100)
        self.finished.emit(f"Folder zaszyfrowany: {os.path.basename(self.output_path)}")
        
      except Exception as e:
        self.error.emit(str(e))

class FolderDecryptWorker(QThread):
    progress = pyqtSignal(int)
    status = pyqtSignal(str)
    finished = pyqtSignal(str)
    error = pyqtSignal(str)
    
    def __init__(self, crypto, password, encrypted_path, output_folder):
        super().__init__()
        self.crypto = crypto
        self.password = password
        self.encrypted_path = encrypted_path
        self.output_folder = output_folder
        self.CHUNK_SIZE = 50 * 1024 * 1024
    
    def run(self):
        try:
            self.status.emit("Odczytywanie pliku...")
            
            with open(self.encrypted_path, 'rb') as f_in:
                # Sprawdź wersję
                version = f_in.read(4).decode('utf-8')
                
                if version == self.crypto.CASCADE_VERSION:
                    self._decrypt_cascade(f_in)
                elif version == self.crypto.ENCRYPTION_VERSION:
                    self._decrypt_aes(f_in)
                else:
                    raise ValueError(f"Nieobsługiwana wersja: {version}")
            
        except Exception as e:
            self.error.emit(str(e))
    
    def _decrypt_aes(self, f_in):
        """Standardowe odszyfrowywanie AES-GCM"""
        salt = f_in.read(16)
        nonce_base = f_in.read(12)
        num_chunks = int.from_bytes(f_in.read(8), 'big')
        
        self.progress.emit(10)
        self.status.emit("Deszyfrowanie danych...")
        
        key = self.crypto.generate_key(self.password, salt)
        
        temp_dir = tempfile.mkdtemp()
        temp_zip = os.path.join(temp_dir, "temp_folder.zip")
        
        aesgcm = AESGCM(key)
        
        with open(temp_zip, 'wb') as f_out:
            for chunk_idx in range(num_chunks):
                chunk_len = int.from_bytes(f_in.read(4), 'big')
                encrypted_chunk = f_in.read(chunk_len)
                
                nonce = nonce_base + chunk_idx.to_bytes(4, 'big')
                decrypted_chunk = aesgcm.decrypt(nonce, encrypted_chunk, None)
                f_out.write(decrypted_chunk)
                
                if num_chunks > 0:
                    self.progress.emit(10 + int((chunk_idx / num_chunks) * 40))
        
        self._extract_zip(temp_zip)
    
    def _decrypt_cascade(self, f_in):
      """Odszyfrowywanie kaskadowe"""
      aes_salt = f_in.read(16)
      aes_nonce_base = f_in.read(12)
      serpent_salt = f_in.read(16)
      num_chunks = int.from_bytes(f_in.read(8), 'big')
    
      self.progress.emit(10)
      self.status.emit("Deszyfrowanie kaskadowe...")
    
      aes_key = self.crypto.generate_key(self.password, aes_salt)
      serpent_key = self.crypto.generate_serpent_key(self.password, serpent_salt)
    
      temp_dir = tempfile.mkdtemp()
      temp_zip = os.path.join(temp_dir, "temp_folder.zip")
    
      from cryptography.hazmat.primitives.ciphers.aead import AESGCM
      aesgcm = AESGCM(aes_key)
    
      with open(temp_zip, 'wb') as f_out:
        for chunk_idx in range(num_chunks):
            chunk_len = int.from_bytes(f_in.read(4), 'big')
            serpent_encrypted = f_in.read(chunk_len)
            
            # Krok 1: Odszyfruj Serpent
            try:
                decrypted_combined = serpent_cbc_decrypt(serpent_key, serpent_encrypted)
                
                # Wyciągnij IV i dane
                # IV jest na pierwszych 16 bajtach
                chunk_iv = decrypted_combined[:16]
                padded_aes = decrypted_combined[16:]
                
                # Usuń padding
                aes_encrypted = self.crypto._unpad_pkcs7(padded_aes)
                
            except Exception as e:
                raise ValueError(f"Błąd deszyfrowania Serpent: {e}")
            
            # Krok 2: Odszyfruj AES
            aes_nonce = aes_nonce_base + chunk_idx.to_bytes(4, 'big')
            try:
                decrypted_chunk = aesgcm.decrypt(aes_nonce, aes_encrypted, None)
                f_out.write(decrypted_chunk)
            except Exception as e:
                raise ValueError(f"Błąd deszyfrowania AES: {e}")
            
            if num_chunks > 0:
                self.progress.emit(10 + int((chunk_idx / num_chunks) * 40))
    
      self._extract_zip(temp_zip)
    
    def _extract_zip(self, temp_zip):
        """Wypakowuje pliki ZIP i czyści"""
        self.status.emit("Wypakowywanie plików...")
        
        if not zipfile.is_zipfile(temp_zip):
            raise ValueError("Odszyfrowane dane nie są prawidłowym archiwum ZIP")
        
        with zipfile.ZipFile(temp_zip, 'r') as zipf:
            files = zipf.namelist()
            for i, name in enumerate(files):
                safe_path = os.path.normpath(os.path.join(self.output_folder, name))
                if not safe_path.startswith(os.path.normpath(self.output_folder)):
                    raise ValueError("Wykryto niebezpieczną ścieżkę w archiwum")
                
                zipf.extract(name, self.output_folder)
                self.progress.emit(50 + int(((i + 1) / len(files)) * 50))
        
        self._secure_delete(temp_zip)
        temp_dir = os.path.dirname(temp_zip)
        shutil.rmtree(temp_dir, ignore_errors=True)
        
        self.progress.emit(100)
        self.finished.emit(f"Folder odszyfrowany do: {os.path.basename(self.output_folder)}")
    
    def _secure_delete(self, file_path):
        if os.path.exists(file_path):
            try:
                with open(file_path, 'wb') as f:
                    f.write(b'\x00' * os.path.getsize(file_path))
                os.remove(file_path)
            except:
                pass


class SafePadApp:
    """Główna klasa aplikacji - łączy GUI z logiką"""
    
    def __init__(self):
        self.password = None
        self.current_file = None
        self.crypto_worker = None
        self.backup_password = DEFAULT_BACKUP_PASSWORD
        
        # Wczytaj ustawienia
        self.settings = Registryconf.load_settings()
        
        # Inicjalizuj szyfrowanie
        encryption_level = self.settings.get("encryption_level", "medium")
        self.crypto = EncryptionCEO(encryption_level)
        
        # GUI
        self.gui = SafePadGUI()
        
        # Podłącz sygnały
        self.connect_signals()
        
        # Przywróć sesję
        self.load_from_temp_file()
        
        # Pokaż okno
        self.gui.showMaximized()
        
        # Inicjalizuj domyślne parametry Argon2 w rejestrze jeśli nie istnieją
        self.init_argon_params()
    
    def connect_signals(self):
        """Podłącz wszystkie sygnały z GUI"""
        
        # === MENU "Plik" ===
        for action in self.gui.menuBar().actions():
            if action.text() == "Plik":
                for act in action.menu().actions():
                    text = act.text()
                    if text == "Nowy":
                        act.triggered.connect(self.new_file)
                    elif text == "Otwórz...":
                        act.triggered.connect(self.open_file)
                    elif text == "Zapisz...":
                        act.triggered.connect(self.save_file)
                    elif text == "Tryb tylko do odczytu":
                        act.triggered.connect(self.toggle_read_only)
                    elif text == "Zaszyfruj folder":
                        act.triggered.connect(self.encrypt_folder)
                    elif text == "Odszyfruj folder":
                        act.triggered.connect(self.decrypt_folder)
                    elif text == "Zakończ":
                        act.triggered.connect(self.on_exit)
                break
        
        # === MENU "Edycja" ===
        for action in self.gui.menuBar().actions():
            if action.text() == "Edycja":
                for act in action.menu().actions():
                    text = act.text()
                    if text == "Cofnij":
                        act.triggered.connect(self.gui.text_edit.undo)
                    elif text == "Ponów":
                        act.triggered.connect(self.gui.text_edit.redo)
                    elif text == "Wytnij":
                        act.triggered.connect(self.gui.text_edit.cut)
                    elif text == "Kopiuj":
                        act.triggered.connect(self.gui.text_edit.copy)
                    elif text == "Wklej":
                        act.triggered.connect(self.gui.text_edit.paste)
                    elif text == "Zaznacz wszystko":
                        act.triggered.connect(self.gui.text_edit.selectAll)
                break
        
        # === MENU "Ustawienia" ===
        for action in self.gui.menuBar().actions():
            if action.text() == "Ustawienia":
                for act in action.menu().actions():
                    if act.text() == "Panel ustawień":
                        act.triggered.connect(self.open_settings)
                break
        
        # === MENU "Pomoc" ===
        for action in self.gui.menuBar().actions():
            if action.text() == "Pomoc":
                for act in action.menu().actions():
                    if act.text() == "O programie":
                        act.triggered.connect(self.show_about)
                break
        
        # === TOOLBAR ===
        for btn in self.gui.toolbar.findChildren(QPushButton):
            text = btn.text()
            if "Nowy" in text:
                btn.clicked.connect(self.new_file)
            elif "Otwórz" in text:
                btn.clicked.connect(self.open_file)
            elif "Zapisz" in text:
                btn.clicked.connect(self.save_file)
            elif "Wytnij" in text:
                btn.clicked.connect(self.gui.text_edit.cut)
            elif "Kopiuj" in text:
                btn.clicked.connect(self.gui.text_edit.copy)
            elif "Wklej" in text:
                btn.clicked.connect(self.gui.text_edit.paste)
        
        # === SYSTEM TRAY ===
        if hasattr(self.gui, 'tray_icon') and self.gui.tray_icon:
            for action in self.gui.tray_icon.contextMenu().actions():
                text = action.text()
                if text == "Pokaż SafePad":
                    action.triggered.connect(self.show_normal)
                elif text == "Zakończ":
                    action.triggered.connect(self.on_exit)
    
    def init_argon_params(self):
        """Inicjalizuje domyślne parametry Argon2 w rejestrze"""
        for level, params in Registryconf.DEFAULT_ARGON_PARAMS.items():
            # Sprawdź czy istnieją, jeśli nie - zapisz
            existing = Registryconf.load_argon_conf(level)
            if existing == Registryconf.DEFAULT_ARGON_PARAMS.get(level):
                Registryconf.save_argon_conf(level, params)
    
    # ------------------------- Operacje na plikach -------------------------
    
    def new_file(self):
        self.gui.text_edit.clear()
        self.current_file = None
        self.password = None
        self.gui.update_label()
        self.gui.update_status("Nowy plik utworzony")
    
    def open_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self.gui, "Otwórz plik", "",
            "SafePad Files (*.sscr);;All Files (*.*)"
        )
        if not file_path:
            return
        
        password, ok = QInputDialog.getText(
            self.gui, "Hasło", "Podaj hasło:", QLineEdit.EchoMode.Password
        )
        if not ok or not password:
            return
        
        try:
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = self.crypto.decrypt_data(password, encrypted_data)
            self.gui.text_edit.setPlainText(decrypted_data.decode('utf-8'))
            
            self.password = password
            self.current_file = file_path
            self.gui.update_label()
            self.gui.update_status(f"Otwarto: {os.path.basename(file_path)}")
            
        except Exception as e:
            QMessageBox.critical(self.gui, "Błąd", f"Nieprawidłowe hasło lub plik uszkodzony.\n\n{e}")
    
    def save_file(self):
        if self.current_file:
            self._save_current_file(self.current_file)
        else:
            self.save_as_file()
    
    def save_as_file(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self.gui, "Zapisz plik jako", "",
            "SafePad Files (*.sscr);;All Files (*.*)"
        )
        if file_path:
            if not file_path.endswith('.sscr'):
                file_path += '.sscr'
            self.current_file = file_path
            self._save_current_file(file_path)
    
    def _save_current_file(self, file_path):
        try:
            if not self.password:
                pwd, ok = QInputDialog.getText(
                    self.gui, "Nowe hasło", "Hasło:", QLineEdit.EchoMode.Password
                )
                if not ok or not pwd:
                    return False
                
                confirm, ok = QInputDialog.getText(
                    self.gui, "Potwierdź", "Powtórz hasło:", QLineEdit.EchoMode.Password
                )
                if not ok or pwd != confirm:
                    QMessageBox.critical(self.gui, "Błąd", "Hasła nie są identyczne!")
                    return False
                self.password = pwd
            
            text = self.gui.text_edit.toPlainText()
            encrypted_data = self.crypto.encrypt_data(self.password, text.encode('utf-8'))
            
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)
            
            self.gui.update_status(f"Zapisano: {os.path.basename(file_path)}")
            self.gui.text_edit.document().setModified(False)
            self.gui.update_label()
            return True
            
        except Exception as e:
            QMessageBox.critical(self.gui, "Błąd", f"Nie udało się zapisać: {e}")
            return False
    
    def toggle_read_only(self):
        is_read_only = self.gui.text_edit.isReadOnly()
        self.gui.text_edit.setReadOnly(not is_read_only)
        status = "Tryb tylko do odczytu" if not is_read_only else "Edycja włączona"
        self.gui.update_status(status)
    
    # ------------------------- Operacje na folderach -------------------------
    
    def encrypt_folder(self):
        folder_path = QFileDialog.getExistingDirectory(self.gui, "Wybierz folder do zaszyfrowania")
        if not folder_path:
            return
        
        default_name = os.path.basename(folder_path) + ".enc"
        output_path, _ = QFileDialog.getSaveFileName(
            self.gui, "Zapisz zaszyfrowany folder", default_name,
            "Encrypted Folder (*.enc);;All Files (*.*)"
        )
        if not output_path:
            return
        
        if not output_path.endswith('.enc'):
            output_path += '.enc'
        
        password, ok = QInputDialog.getText(
            self.gui, "Hasło", "Hasło do szyfrowania folderu:", QLineEdit.EchoMode.Password
        )
        if not ok or not password:
            return
        
        confirm, ok = QInputDialog.getText(
            self.gui, "Potwierdź", "Powtórz hasło:", QLineEdit.EchoMode.Password
        )
        if not ok or password != confirm:
            QMessageBox.critical(self.gui, "Błąd", "Hasła nie są identyczne!")
            return
        
        self.progress = QProgressDialog("Przygotowywanie...", "Anuluj", 0, 100, self.gui)
        self.progress.setWindowTitle("Szyfrowanie folderu")
        self.progress.setWindowModality(Qt.WindowModality.WindowModal)
        self.progress.setAutoClose(True)
        self.progress.setMinimumDuration(0)
        
        self.crypto_worker = FolderEncryptWorker(self.crypto, password, folder_path, output_path)
        self.crypto_worker.progress.connect(self.progress.setValue)
        self.crypto_worker.status.connect(self.progress.setLabelText)
        self.crypto_worker.finished.connect(self._on_encrypt_finished)
        self.crypto_worker.error.connect(self._on_crypto_error)
        self.progress.canceled.connect(self._cancel_crypto)
        
        self.crypto_worker.start()
        self.progress.exec()
    
    def decrypt_folder(self):
        encrypted_path, _ = QFileDialog.getOpenFileName(
            self.gui, "Wybierz zaszyfrowany folder", "",
            "Encrypted Folder (*.enc);;All Files (*.*)"
        )
        if not encrypted_path:
            return
        
        base_name = os.path.basename(encrypted_path)
        if base_name.lower().endswith('.enc'):
            folder_name = base_name[:-4]
        else:
            folder_name = base_name + "_decrypted"
        
        output_folder = QFileDialog.getExistingDirectory(
            self.gui, "Wybierz lokalizację dla odszyfrowanego folderu",
            os.path.dirname(encrypted_path)
        )
        if not output_folder:
            return
        
        final_output_path = os.path.join(output_folder, folder_name)
        
        if os.path.exists(final_output_path):
            reply = QMessageBox.question(
                self.gui, "Folder istnieje",
                f"Folder '{folder_name}' już istnieje.\nCzy chcesz go nadpisać?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.No:
                return
            try:
                shutil.rmtree(final_output_path)
            except:
                pass
        
        password, ok = QInputDialog.getText(
            self.gui, "Hasło", "Hasło do odszyfrowania:", QLineEdit.EchoMode.Password
        )
        if not ok or not password:
            return
        
        self.progress = QProgressDialog("Przygotowywanie...", "Anuluj", 0, 100, self.gui)
        self.progress.setWindowTitle("Odszyfrowywanie folderu")
        self.progress.setWindowModality(Qt.WindowModality.WindowModal)
        self.progress.setAutoClose(True)
        self.progress.setMinimumDuration(0)
        
        self.crypto_worker = FolderDecryptWorker(self.crypto, password, encrypted_path, final_output_path)
        self.crypto_worker.progress.connect(self.progress.setValue)
        self.crypto_worker.status.connect(self.progress.setLabelText)
        self.crypto_worker.finished.connect(self._on_decrypt_finished)
        self.crypto_worker.error.connect(self._on_crypto_error)
        self.progress.canceled.connect(self._cancel_crypto)
        
        self.crypto_worker.start()
        self.progress.exec()
    
    def _cancel_crypto(self):
        if self.crypto_worker and self.crypto_worker.isRunning():
            self.crypto_worker.terminate()
            self.crypto_worker.wait()
            self.progress.close()
            self.gui.update_status("Operacja anulowana", is_error=True)
    
    def _on_encrypt_finished(self, message):
        self.progress.close()
        self.gui.update_status(message)
        QMessageBox.information(self.gui, "Sukces", message)
    
    def _on_decrypt_finished(self, message):
        self.progress.close()
        self.gui.update_status(message)
        QMessageBox.information(self.gui, "Sukces", f"Folder odszyfrowany pomyślnie!\n\n{message}")
    
    def _on_crypto_error(self, error_msg):
        self.progress.close()
        self.gui.update_status("Błąd", is_error=True)
        QMessageBox.critical(self.gui, "Błąd", error_msg)
    
    # ------------------------- Sesja -------------------------
    
    def load_backup_password(self):
        """Wczytaj własne hasło do backupów z rejestru"""
        try:
            stored_password = Registryconf.load_backup_password()
            if stored_password:
                self.backup_password = stored_password
        except:
            # Jeśli nie można wczytać, użyj domyślnego
            self.backup_password = DEFAULT_BACKUP_PASSWORD
            
            
    def set_backup_password(self):
        """Ustaw własne hasło do backupów sesji"""
        # Zapytaj o nowe hasło
        new_password, ok = QInputDialog.getText(
            self.gui, 
            "Hasło do backupów sesji", 
            "Wprowadź nowe hasło do backupów sesji\n(lub pozostaw puste, aby użyć domyślnego):", 
            QLineEdit.EchoMode.Password
        )
        
        if not ok:
            return False
        
        if not new_password:
            # Przywróć domyślne hasło
            self.backup_password = DEFAULT_BACKUP_PASSWORD
            Registryconf.delete_backup_password()
            
            QMessageBox.information(
                self.gui, 
                "Hasło zresetowane", 
                "Przywrócono domyślne hasło do backupów sesji."
            )
            return True
        
        confirm_password, ok = QInputDialog.getText(
            self.gui, 
            "Potwierdź hasło", 
            "Powtórz hasło do backupów sesji:", 
            QLineEdit.EchoMode.Password
        )
        
        if not ok:
            return False
        
        if new_password != confirm_password:
            QMessageBox.critical(
                self.gui, 
                "Błąd", 
                "Hasła nie są identyczne!"
            )
            return False
        
        # Zapisz nowe hasło
        self.backup_password = new_password
        Registryconf.save_backup_password(new_password)
        
        QMessageBox.information(
            self.gui, 
            "Hasło zapisane", 
            "Własne hasło do backupów sesji zostało zapisane.\n"
            "Będzie używane przy następnym uruchomieniu programu."
        )
        
        return True
    
    def save_to_temp_file(self):
        """Zapisz sesję do pliku tymczasowego"""
        try:
            temp_file = os.path.join(tempfile.gettempdir(), "safepad_session_backup.sscr")
            text = self.gui.text_edit.toPlainText()
            if text:
                encrypted = self.crypto.encrypt_data(
                    self.backup_password, 
                    text.encode('utf-8')
                )
                with open(temp_file, 'wb') as f:
                    f.write(encrypted)
        except Exception as e:
            print(f"Błąd zapisu sesji: {e}")
    
    def load_from_temp_file(self):
        """Wczytaj sesję z pliku tymczasowego"""
        try:
            temp_file = os.path.join(tempfile.gettempdir(), "safepad_session_backup.sscr")
            if os.path.exists(temp_file):
                with open(temp_file, 'rb') as f:
                    encrypted = f.read()
                
                decrypted = self.crypto.decrypt_data(
                    self.backup_password, 
                    encrypted
                )
                self.gui.text_edit.setPlainText(decrypted.decode('utf-8'))
                self.gui.update_status("Sesja przywrócona")
        except Exception as e:
            print(f"Błąd ładowania sesji: {e}")
    
    # ------------------------- Ustawienia -------------------------
    
    def open_settings(self):
      """Otwórz okno ustawień"""
      from gui.ui import SettingsDialog
      dialog = SettingsDialog(self.gui, self.settings)
      if dialog.exec() == QDialog.DialogCode.Accepted:
        new_settings = dialog.get_settings()
        
        # Zapisz ustawienia do REJESTRU
        Registryconf.save_settings(new_settings)
        
        # Aktualizuj lokalne ustawienia
        self.settings = new_settings
        
        # Aktualizuj szyfrowanie z nowym poziomem
        level = new_settings.get("encryption_level", "medium")
        self.crypto = EncryptionCEO(level)
        
        # Jeśli hasło do backupów zostało zmienione, przeładuj je
        if new_settings.get("backup_password_changed"):
            self.load_backup_password()
        
        self.gui.update_status("Ustawienia zapisane w rejestrze")
    
    def show_about(self):
        about_text = f"""SafePad {APP_VERSION}

Bezpieczny edytor tekstu z szyfrowaniem AES-GCM i Argon2ID.

Autor: {AUTHOR}

Funkcje:
- Szyfrowanie plików
- Szyfrowanie folderów
- Argon2ID z AES-GCM 256
- Automatyczny backup sesji
- Licencja: MIT
"""
        
        QMessageBox.about(self.gui, "O programie", about_text)
    
    def show_normal(self):
        self.gui.show()
        self.gui.activateWindow()
        self.gui.raise_()
    
    def on_exit(self):
        if self.gui.text_edit.toPlainText():
            self.save_to_temp_file()
        QApplication.quit()
        
        
# ------------------------- Argon2Benchmark -------------------------

def run_argon2_benchmark(self):
    """Uruchamia benchmark Argon2ID i zapisuje wyniki"""
    from PyQt6.QtWidgets import QProgressDialog
    
    self.progress = QProgressDialog("Uruchamianie benchmarku...", "Anuluj", 0, 100, self.gui)
    self.progress.setWindowTitle("Benchmark Argon2ID")
    self.progress.setWindowModality(Qt.WindowModality.WindowModal)
    self.progress.setAutoClose(True)
    self.progress.setMinimumDuration(0)
    
    def on_progress(value):
        self.progress.setValue(value)
    
    def on_status(status):
        self.progress.setLabelText(status)
    
    try:
        results = Argon2Benchmark.run_benchmark(
            progress_callback=on_progress,
            status_callback=on_status
        )
        
        # Zapisz wyniki do rejestru
        Argon2Benchmark.save_benchmark_results(Registryconf, results)
        
        self.progress.close()
        QMessageBox.information(
            self.gui, "Benchmark zakończony",
            f"Optymalne parametry dla twojego komputera:\n\n"
            f"Pamięć: {results['m'] // 1024} MB\n"
            f"Iteracje: {results['t']}\n"
            f"Wątki: {results['p']}\n\n"
            f"Parametry zostały zapisane w rejestrze."
        )
        
        # Odśwież szyfrowanie z nowymi parametrami
        self.crypto = EncryptionCEO(self.settings.get("encryption_level", "medium"))
        
    except Exception as e:
        self.progress.close()
        QMessageBox.critical(self.gui, "Błąd", f"Benchmark nie powiódł się:\n{e}")


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    if os.path.exists("safe.ico"):
        app.setWindowIcon(QIcon("safe.ico"))
    
    window = SafePadApp()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()