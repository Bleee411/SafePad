"""
SafePad
Autor: Szofer
Licencja: MIT
Wersja: 2.2.3-BETA
"""

import sys
import os
import secrets
import tempfile
import shutil
import zipfile
from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtWidgets import (QApplication, QMessageBox, QFileDialog, QInputDialog, 
                             QProgressDialog, QLineEdit, QDialog, QPushButton)
from PyQt6.QtGui import QIcon
import ctypes
from PyQt6.QtWidgets import QMenu
from PyQt6.QtGui import QAction

from others.languages import tr, format_tr, LanguageManager
from gui.ui import SafePadGUI
from crypto.encryption_decryption import EncryptionCEO, Registryconf
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pyserpent import serpent_cbc_encrypt, serpent_cbc_decrypt
from others.others import Argon2Benchmark, is_benchmark_needed, secure_delete, check_password_requirements

ctypes.windll.shell32.SHChangeNotify(0x08000000, 0x0000, None, None) 

APP_VERSION = "2.2.3-BETA"
AUTHOR = "Szofer"

# NOTE: kiedyś tutaj istniała jedna stała DEFAULT_BACKUP_PASSWORD zawierająca
# stałe domyslne hasło które nie chroniło kopi zapasowych. Ponieważ kod jest publiczny 
# to "domyślne" hasło tak samo było publiczne, więc "zaszyfrowane" 
# Automatyczne zapisywanie sesji kopiowej było praktycznie niechronione dla każdego użytkownika, który 
# nie ustawił własnego hasła do kopii zapasowej. Został usunięty – zobacz 
# SafePadApp.load_backup_password(), która teraz generuje unikalny losowy obraz 
# hasło na instalację (chronione w spoczynku przez Windows DPAPI w 
# Registryconf.save_backup_password) zamiast wspólnego sekretu wpisanego w nego kod zródłowy.


class _WorkerCancelled(Exception):
    """Sygnalizuje, że użytkownik poprosił o anulowanie operacji - używane
    do współpracującego (cooperative) przerywania wątków szyfrowania /
    deszyfrowania zamiast niebezpiecznego QThread.terminate()."""
    pass


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
        self._cancel_requested = False

    def request_cancel(self):
        """Prosi wątek o zatrzymanie się przy najbliższej bezpiecznej okazji
        (zamiast wymuszania QThread.terminate(), które może przerwać wątek
        w trakcie zapisu/operacji na plikach i zostawić rzeczy w
        niespójnym stanie)."""
        self._cancel_requested = True

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
                # HOTFIX: wcześniej Cancel był sprawdzany tylko w pętli
                # szyfrowania fragmentów, więc dla dużych folderów kliknięcie
                # Anuluj podczas samego pakowania do zip nie miało żadnego
                # efektu aż do zakończenia pakowania.
                if self._cancel_requested:
                    raise _WorkerCancelled()
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
                        if self._cancel_requested:
                            raise _WorkerCancelled()

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
                        if self._cancel_requested:
                            raise _WorkerCancelled()

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
        secure_delete(temp_zip)
        shutil.rmtree(temp_dir, ignore_errors=True)
        
        self.progress.emit(100)
        self.finished.emit(f"Folder zaszyfrowany: {os.path.basename(self.output_path)}")

      except _WorkerCancelled:
        try:
            secure_delete(temp_zip)
        except Exception:
            pass
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass
        try:
            if os.path.exists(self.output_path):
                secure_delete(self.output_path)
        except Exception:
            pass
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
        self._cancel_requested = False

    def request_cancel(self):
        """Prosi wątek o zatrzymanie się przy najbliższej bezpiecznej okazji
        (zamiast QThread.terminate())."""
        self._cancel_requested = True

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
            
        except _WorkerCancelled:
            pass
        except Exception as e:
            error_msg = str(e)
            # Sprawdź czy to błąd hasła
            if any(keyword in error_msg.lower() for keyword in ['hasło', 'password', 'key', 'mac', 'tag', 'auth', 'cipher']):
                self.error.emit("Nieprawidłowe hasło! Sprawdź hasło i spróbuj ponownie.")
            else:
                self.error.emit(f"Błąd deszyfrowania: {error_msg}")
    
    def _decrypt_aes(self, f_in):
        """Standardowe odszyfrowywanie AES-GCM"""
        salt = f_in.read(16)
        nonce_base = f_in.read(12)
        num_chunks = int.from_bytes(f_in.read(8), 'big')
        
        self.progress.emit(10)
        self.status.emit("Deszyfrowanie danych...")
        
        try:
            key = self.crypto.generate_key(self.password, salt)
        except Exception as e:
            raise ValueError(f"Błąd generowania klucza: {e}")
        
        temp_dir = tempfile.mkdtemp()
        temp_zip = os.path.join(temp_dir, "temp_folder.zip")
        
        aesgcm = AESGCM(key)
        
        try:
            with open(temp_zip, 'wb') as f_out:
                for chunk_idx in range(num_chunks):
                    if self._cancel_requested:
                        raise _WorkerCancelled()

                    chunk_len = int.from_bytes(f_in.read(4), 'big')
                    encrypted_chunk = f_in.read(chunk_len)

                    nonce = nonce_base + chunk_idx.to_bytes(4, 'big')
                    try:
                        decrypted_chunk = aesgcm.decrypt(nonce, encrypted_chunk, None)
                    except Exception:
                        raise ValueError("Nieprawidłowe hasło lub uszkodzone dane")

                    f_out.write(decrypted_chunk)

                    if num_chunks > 0:
                        self.progress.emit(10 + int((chunk_idx / num_chunks) * 40))
        except _WorkerCancelled:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise

        self._extract_zip(temp_zip)
    
    def _decrypt_cascade(self, f_in):
        """Odszyfrowywanie kaskadowe"""
        aes_salt = f_in.read(16)
        aes_nonce_base = f_in.read(12)
        serpent_salt = f_in.read(16)
        num_chunks = int.from_bytes(f_in.read(8), 'big')
        
        self.progress.emit(10)
        self.status.emit("Deszyfrowanie kaskadowe...")
        
        try:
            aes_key = self.crypto.generate_key(self.password, aes_salt)
            serpent_key = self.crypto.generate_serpent_key(self.password, serpent_salt)
        except Exception as e:
            raise ValueError(f"Błąd generowania kluczy: {e}")
        
        temp_dir = tempfile.mkdtemp()
        temp_zip = os.path.join(temp_dir, "temp_folder.zip")
        
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(aes_key)
        
        try:
          with open(temp_zip, 'wb') as f_out:
            for chunk_idx in range(num_chunks):
                if self._cancel_requested:
                    raise _WorkerCancelled()

                chunk_len = int.from_bytes(f_in.read(4), 'big')
                serpent_encrypted = f_in.read(chunk_len)
                
                # UWAGA - ochrona przed atakiem typu padding oracle: oba etapy
                # (Serpent-CBC/unpad oraz AES-GCM) muszą zgłaszać identyczny,
                # nieodróżnialny komunikat błędu. Patrz komentarz w
                # crypto/encryption_decryption.py -> _decrypt_cascade.
                generic_error = "Nieprawidłowe hasło lub uszkodzone dane"

                # Krok 1: Odszyfruj Serpent
                try:
                    decrypted_combined = serpent_cbc_decrypt(serpent_key, serpent_encrypted)

                    # Wyciągnij dane (pomijając IV)
                    padded_aes = decrypted_combined[16:]

                    # Usuń padding (pełna walidacja w czasie stałym)
                    aes_encrypted = self.crypto._unpad_pkcs7(padded_aes)

                except Exception:
                    raise ValueError(generic_error)

                # Krok 2: Odszyfruj AES
                aes_nonce = aes_nonce_base + chunk_idx.to_bytes(4, 'big')
                try:
                    decrypted_chunk = aesgcm.decrypt(aes_nonce, aes_encrypted, None)
                    f_out.write(decrypted_chunk)
                except Exception:
                    raise ValueError(generic_error)
                
                if num_chunks > 0:
                    self.progress.emit(10 + int((chunk_idx / num_chunks) * 40))
        except _WorkerCancelled:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise

        self._extract_zip(temp_zip)
    
    def _extract_zip(self, temp_zip):
        """Wypakowuje pliki ZIP do folderu tymczasowego (staging) i dopiero po
        pełnym powodzeniu podmienia docelowy folder. Dzięki temu błędne hasło
        lub uszkodzone dane nigdy nie niszczą istniejącego folderu docelowego."""
        self.status.emit("Wypakowywanie plików...")
        
        if not zipfile.is_zipfile(temp_zip):
            raise ValueError("Odszyfrowane dane nie są prawidłowym archiwum ZIP")
        
        staging_dir = tempfile.mkdtemp(prefix="safepad_extract_")
        try:
            with zipfile.ZipFile(temp_zip, 'r') as zipf:
                files = zipf.namelist()
                staging_root = os.path.normpath(os.path.abspath(staging_dir))
                for i, name in enumerate(files):
                    safe_path = os.path.normpath(os.path.abspath(os.path.join(staging_root, name)))
                    # Use os.path.commonpath instead of startswith to avoid the classic
                    # "C:\out" matching "C:\out_evil" prefix bypass.
                    if os.path.commonpath([staging_root, safe_path]) != staging_root:
                        raise ValueError("Wykryto niebezpieczną ścieżkę w archiwum")
                    
                    zipf.extract(name, staging_dir)
                    self.progress.emit(50 + int(((i + 1) / len(files)) * 40))
            
            # Wypakowanie się powiodło - dopiero teraz można bezpiecznie
            # podmienić istniejący folder docelowy (jeśli istnieje).
            if os.path.exists(self.output_folder):
                shutil.rmtree(self.output_folder)
            
            parent_dir = os.path.dirname(os.path.normpath(self.output_folder))
            if parent_dir:
                os.makedirs(parent_dir, exist_ok=True)
            shutil.move(staging_dir, self.output_folder)
            
        except Exception:
            # Cokolwiek pójdzie nie tak, sprzątamy staging i nie ruszamy
            # istniejącego folderu docelowego.
            shutil.rmtree(staging_dir, ignore_errors=True)
            raise
        
        secure_delete(temp_zip)
        temp_dir = os.path.dirname(temp_zip)
        shutil.rmtree(temp_dir, ignore_errors=True)
        
        self.progress.emit(100)
        self.finished.emit(f"Folder odszyfrowany do: {os.path.basename(self.output_folder)}")


class SafePadApp:
    """Główna klasa aplikacji - łączy GUI z logiką"""
    
    def __init__(self):
        self.password = None
        self.current_file = None
        self.crypto_worker = None
        self.backup_password = None
        
        # Wczytaj ustawienia
        self.settings = Registryconf.load_settings()
        
        # Inicjalizuj szyfrowanie
        encryption_level = self.settings.get("encryption_level", "medium")
        self.crypto = EncryptionCEO(encryption_level)
        
        # Wczytaj (lub wygeneruj przy pierwszym uruchomieniu) hasło do
        # backupów sesji - musi być gotowe zanim spróbujemy odczytać
        # ewentualną istniejącą sesję poniżej.
        self.load_backup_password()
        
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
    
    @staticmethod
    def _safe_connect(signal, slot):
        """
        HOTFIX: łączy sygnał ze slotem w sposób idempotentny.

        connect_signals() bywa wywoływane wielokrotnie (np. po każdej
        zmianie języka przez change_language()). Wcześniej tylko akcje
        menu językowego były zabezpieczone przed podwójnym podłączeniem
        (disconnect() przed connect()) - reszta sygnałów (new_action,
        save_action, przyciski toolbara itd.) nie miała takiej ochrony.

        Jeśli GUI.update_language() nie tworzy tych widgetów od nowa
        (tylko np. zmienia im tekst), każda zmiana języka dokładałaby
        kolejne połączenie do tego samego slotu, przez co np. zapis pliku
        albo otwarcie okna dialogowego uruchamiałoby się wielokrotnie po
        jednym kliknięciu. Ta metoda usuwa WSZYSTKIE istniejące połączenia
        danego sygnału przed podłączeniem nowego, więc wynik jest zawsze
        dokładnie jedno aktywne połączenie - niezależnie od tego, czy
        widget jest tworzony od nowa, czy tylko odświeżany.
        """
        try:
            signal.disconnect()
        except (TypeError, RuntimeError):
            # Brak istniejących połączeń (lub sygnał już nieaktywny) - to
            # oczekiwane przy pierwszym wywołaniu connect_signals().
            pass
        signal.connect(slot)

    def connect_signals(self):
      """Podłącz wszystkie sygnały z GUI - używając referencji do obiektów"""
      sc = self._safe_connect

      # === MENU "Plik" ===
      if hasattr(self.gui, 'new_action'):
          sc(self.gui.new_action.triggered, self.new_file)
          sc(self.gui.open_action.triggered, self.open_file)
          sc(self.gui.save_action.triggered, self.save_file)
          sc(self.gui.read_only_action.triggered, self.toggle_read_only)
          sc(self.gui.encrypt_folder_action.triggered, self.encrypt_folder)
          sc(self.gui.decrypt_folder_action.triggered, self.decrypt_folder)
          sc(self.gui.exit_action.triggered, self.on_exit)
    
      # === MENU "Edycja" ===
      if hasattr(self.gui, 'undo_action'):
          sc(self.gui.undo_action.triggered, self.gui.text_edit.undo)
          sc(self.gui.redo_action.triggered, self.gui.text_edit.redo)
          sc(self.gui.cut_action.triggered, self.gui.text_edit.cut)
          sc(self.gui.copy_action.triggered, self.gui.text_edit.copy)
          sc(self.gui.paste_action.triggered, self.gui.text_edit.paste)
          sc(self.gui.select_all_action.triggered, self.gui.text_edit.selectAll)
    
      # === MENU "Ustawienia" ===
      if hasattr(self.gui, 'settings_panel_action'):
          sc(self.gui.settings_panel_action.triggered, self.open_settings)
    
      # === MENU "Pomoc" ===
      if hasattr(self.gui, 'about_action'):
          sc(self.gui.about_action.triggered, self.show_about)
    
      # === MENU "Język" ===
      if hasattr(self.gui, 'language_actions'):
          for code, action in self.gui.language_actions.items():
              sc(action.triggered, lambda checked, c=code: self.change_language(c))
    
      # === TOOLBAR ===
      if hasattr(self.gui, 'toolbar_buttons'):
          buttons = self.gui.toolbar_buttons
          if len(buttons) > 0 and buttons[0]:
              sc(buttons[0].clicked, self.new_file)
          if len(buttons) > 1 and buttons[1]:
              sc(buttons[1].clicked, self.open_file)
          if len(buttons) > 2 and buttons[2]:
              sc(buttons[2].clicked, self.save_file)
          if len(buttons) > 4 and buttons[4]:
              sc(buttons[4].clicked, self.gui.text_edit.cut)
          if len(buttons) > 5 and buttons[5]:
              sc(buttons[5].clicked, self.gui.text_edit.copy)
          if len(buttons) > 6 and buttons[6]:
              sc(buttons[6].clicked, self.gui.text_edit.paste)
    
      # === SYSTEM TRAY ===
      if hasattr(self.gui, 'tray_icon') and self.gui.tray_icon:
          pass
    
    def init_argon_params(self):
        """Inicjalizuje domyślne parametry Argon2 w rejestrze"""
        for level, params in Registryconf.DEFAULT_ARGON_PARAMS.items():
            # Sprawdź czy istnieją, jeśli nie - zapisz
            existing = Registryconf.load_argon_conf(level)
            if existing == Registryconf.DEFAULT_ARGON_PARAMS.get(level):
                Registryconf.save_argon_conf(level, params)
                
    def change_language(self, language_code):
      """Change application language without restart"""
      from others.languages import LanguageManager
    
      lang_manager = LanguageManager()
      current_lang = lang_manager.get_language()
    
      if language_code != current_lang:
          lang_manager.save_language(language_code)
        
          # Zapisz bieżący tekst
          current_text = self.gui.text_edit.toPlainText()
          current_file = self.current_file
        
          # Odśwież całe GUI
          self.gui.update_language()
        
          # Przywróć tekst
          self.gui.text_edit.setPlainText(current_text)
          self.current_file = current_file
          self.gui.current_file = current_file
          self.gui.update_label()
        
          # Ponownie podłącz sygnały
          self.connect_signals()
        
          self.gui.update_status(f"Język zmieniony na {lang_manager.get_language_name()}")
    
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
                
                is_valid, errors = check_password_requirements(pwd, self.settings)
                if not is_valid:
                    QMessageBox.critical(
                        self.gui, "Hasło nie spełnia wymagań",
                        "Hasło nie spełnia skonfigurowanych wymagań bezpieczeństwa:\n\n"
                        + "\n".join(f"• {e}" for e in errors)
                    )
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
        
        is_valid, errors = check_password_requirements(password, self.settings)
        if not is_valid:
            QMessageBox.critical(
                self.gui, "Hasło nie spełnia wymagań",
                "Hasło nie spełnia skonfigurowanych wymagań bezpieczeństwa:\n\n"
                + "\n".join(f"• {e}" for e in errors)
            )
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
            # UWAGA: folder docelowy NIE jest usuwany tutaj. Dopiero po
            # pomyślnym odszyfrowaniu i wypakowaniu (patrz FolderDecryptWorker
            # ._extract_zip) zostanie on nadpisany, żeby błędne hasło nie
            # zniszczyło istniejących danych użytkownika.
        
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
            output_path = getattr(self.crypto_worker, 'output_path', None) or \
                          getattr(self.crypto_worker, 'output_folder', None)

            # Proś wątek o zatrzymanie się przy najbliższej bezpiecznej okazji
            # (między chunkami) zamiast wymuszać terminate(), które może
            # przerwać wątek w trakcie zapisu do pliku i zostawić dane w
            # niespójnym stanie (np. częściowo zapisany plik/uszkodzony
            # folder tymczasowy).
            self.crypto_worker.request_cancel()
            self.crypto_worker.wait()
            self.progress.close()
            
            try:
                if output_path and os.path.isfile(output_path):
                    secure_delete(output_path)
                elif output_path and os.path.isdir(output_path):
                    shutil.rmtree(output_path, ignore_errors=True)
            except Exception:
                pass
            
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
    
      if "nieprawidłowe hasło" in error_msg.lower() or "invalid password" in error_msg.lower():
          QMessageBox.critical(
              self.gui, 
              "Błąd hasła", 
              "Nieprawidłowe hasło!\n\n"
              "Sprawdź czy wprowadzone hasło jest poprawne.\n"
              "Hasła rozróżniają wielkość liter."
        )
      else:
          QMessageBox.critical(self.gui, "Błąd", error_msg)
    
    # ------------------------- Sesja -------------------------
    
    @staticmethod
    def _generate_backup_password():
        """Generuje losowe, unikalne dla tej instalacji hasło do backupów sesji."""
        return secrets.token_urlsafe(32)
    
    def load_backup_password(self):
        """Wczytaj hasło do backupów sesji z rejestru (chronione Windows DPAPI).
        
        Jeśli żadne hasło nie zostało jeszcze zapisane (pierwsze uruchomienie),
        lub nie da się go odszyfrować (np. inny użytkownik/komputer), generujemy
        nowe, losowe hasło unikalne dla tej instalacji zamiast polegać na
        jednym haśle domyślnym wspólnym dla wszystkich instalacji programu."""
        try:
            stored_password = Registryconf.load_backup_password()
        except Exception:
            stored_password = None
        
        if stored_password:
            self.backup_password = stored_password
        else:
            self.backup_password = self._generate_backup_password()
            Registryconf.save_backup_password(self.backup_password)
    
    def set_backup_password(self):
        """Ustaw własne hasło do backupów sesji"""
        # Zapytaj o nowe hasło
        new_password, ok = QInputDialog.getText(
            self.gui, 
            "Hasło do backupów sesji", 
            "Wprowadź nowe hasło do backupów sesji\n(lub pozostaw puste, aby wygenerować nowe losowe hasło):", 
            QLineEdit.EchoMode.Password
        )
        
        if not ok:
            return False
        
        if not new_password:
            # Wygeneruj nowe, losowe hasło (nigdy nie przywracamy jednego,
            # wspólnego dla wszystkich instalacji hasła domyślnego).
            self.backup_password = self._generate_backup_password()
            Registryconf.save_backup_password(self.backup_password)
            
            QMessageBox.information(
                self.gui, 
                "Hasło zresetowane", 
                "Wygenerowano nowe, losowe hasło do backupów sesji."
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

🛡️ Bezpieczny Edytor Tekstu
Autor: {AUTHOR}

Licencja: MIT (Open-Source)

Ten projekt to nowoczesny, wydajny i zorientowany na prywatność edytor tekstu napisany w języku Python. Został zaprojektowany z myślą o maksymalnej ochronie poufności danych. Dzięki implementacji najnowocześniejszych standardów kryptograficznych, aplikacja gwarantuje, że Twoje notatki, kody źródłowe czy prywatne dokumenty pozostaną w 100% bezpieczne – nawet w przypadku fizycznego przejęcia nośnika danych czy ataku na urządzenie.

✨ Główne funkcje i możliwości
Wszechstronne szyfrowanie danych (Pliki i Foldery)
Aplikacja pozwala nie tylko na zabezpieczanie pojedynczych plików tekstowych, ale umożliwia również szyfrowanie całych katalogów. Ułatwia to zarządzanie większymi zasobami i masowe zabezpieczanie dokumentów bez konieczności szyfrowania każdego pliku z osobna.

Wysokiej klasy bezpieczeństwo kryptograficzne

Kluczowanie (KDF): Do wyprowadzania klucza kryptograficznego z hasła użytkownika wykorzystywany jest algorytm Argon2ID (zwycięzca Password Hashing Competition). Zapewnia on potężną ochronę przed atakami słownikowymi, atakami typu brute-force oraz łamaniem haseł przy użyciu układów GPU.

Szyfrowanie i autentykacja: Użytkownik ma do wyboru dwa zaawansowane algorytmy szyfrujące operujące w trybie uwierzytelnionym (AEAD):

AES-GCM 256-bit: Aktualny, niezwykle szybki standard branżowy.

Serpent 256 GCM: Alternatywny algorytm o bardzo konserwatywnej budowie, znany z ogromnego marginesu bezpieczeństwa.
Dzięki wykorzystaniu trybu GCM (Galois/Counter Mode), edytor zapewnia nie tylko poufność, ale też chroni integralność danych – program natychmiast wykryje każdą próbę modyfikacji lub uszkodzenia zaszyfrowanego pliku z zewnątrz.

Automatyczny backup sesji (Auto-Save)
System dba o to, abyś nigdy nie stracił niezapisanej pracy. W tle automatycznie tworzone są zaszyfrowane kopie zapasowe (snapshoty) aktualnej sesji. W przypadku awarii zasilania, nieoczekiwanego zamknięcia programu lub błędu systemu operacyjnego, Twoje dane mogą zostać szybko i bezpiecznie odzyskane tuż po ponownym uruchomieniu edytora.

Pełna transparentność (Licencja MIT)
Kod programu jest otwarty. Możesz swobodnie z niego korzystać, audytować pod kątem bezpieczeństwa, modyfikować i dostosowywać do własnych, specyficznych potrzeb – zarówno w projektach prywatnych, jak i komercyjnych.
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
        

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    if os.path.exists("safe.ico"):
        app.setWindowIcon(QIcon("safe.ico"))
    
    window = SafePadApp()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()