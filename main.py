"""
SafePad
Autor: Szofer
Licencja: MIT
Wersja: 2.2.3-BETA-4
"""

import sys
import os
import secrets
import tempfile
import shutil
import zipfile
import uuid
from datetime import datetime, timezone
from PyQt6.QtCore import QThread, pyqtSignal, Qt, QTimer
from PyQt6.QtWidgets import (QApplication, QMessageBox, QFileDialog, QInputDialog, 
                             QProgressDialog, QLineEdit, QDialog)
from PyQt6.QtGui import QIcon
import ctypes

from others.languages import LanguageManager
from gui.ui import SafePadGUI
from crypto.encryption_decryption import EncryptionCEO, Registryconf, VaultFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pyserpent import serpent_cbc_encrypt, serpent_cbc_decrypt
from others.others import secure_delete, check_password_requirements

ctypes.windll.shell32.SHChangeNotify(0x08000000, 0x0000, None, None) 

APP_VERSION = "2.2.3-BETA-4"
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

                    chunk_len_bytes = f_in.read(4)
                    if len(chunk_len_bytes) != 4:
                        raise ValueError("Nieprawidłowe hasło lub uszkodzone dane")
                    chunk_len = int.from_bytes(chunk_len_bytes, 'big')
                    # HOTFIX: chunk_len pochodzi z pliku (może być uszkodzony
                    # lub spreparowany) - walidujemy zakres i sprawdzamy, czy
                    # rzeczywiście udało się wczytać zadeklarowaną liczbę
                    # bajtów, zamiast bez ograniczeń próbować f_in.read()
                    # na dowolnie dużą, potencjalnie fałszywą długość.
                    if chunk_len < 0 or chunk_len > self.CHUNK_SIZE + 64:
                        raise ValueError("Nieprawidłowe hasło lub uszkodzone dane")
                    encrypted_chunk = f_in.read(chunk_len)
                    if len(encrypted_chunk) != chunk_len:
                        raise ValueError("Nieprawidłowe hasło lub uszkodzone dane")

                    nonce = nonce_base + chunk_idx.to_bytes(4, 'big')
                    try:
                        decrypted_chunk = aesgcm.decrypt(nonce, encrypted_chunk, None)
                    except Exception:
                        raise ValueError("Nieprawidłowe hasło lub uszkodzone dane")

                    f_out.write(decrypted_chunk)

                    if num_chunks > 0:
                        self.progress.emit(10 + int((chunk_idx / num_chunks) * 40))
        except Exception:
            # HOTFIX: wcześniej tylko _WorkerCancelled czyściło temp_dir - każdy
            # inny błąd (złe hasło, uszkodzony plik) zostawiał częściowo
            # odszyfrowany plaintext ZIP w %TEMP% na zawsze.
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

                chunk_len_bytes = f_in.read(4)
                if len(chunk_len_bytes) != 4:
                    raise ValueError("Nieprawidłowe hasło lub uszkodzone dane")
                chunk_len = int.from_bytes(chunk_len_bytes, 'big')
                # HOTFIX: walidacja długości chunku pochodzącej z pliku - patrz
                # analogiczny komentarz w _decrypt_aes powyżej.
                if chunk_len < 0 or chunk_len > self.CHUNK_SIZE + 64:
                    raise ValueError("Nieprawidłowe hasło lub uszkodzone dane")
                serpent_encrypted = f_in.read(chunk_len)
                if len(serpent_encrypted) != chunk_len:
                    raise ValueError("Nieprawidłowe hasło lub uszkodzone dane")
                
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
        except Exception:
            # HOTFIX: patrz komentarz w _decrypt_aes - czyścimy temp_dir na
            # KAŻDYM błędzie, nie tylko na anulowaniu.
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
                    if files:
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

        # HOTFIX: self.gui.settings zostawało {} od __init__ SafePadGUI aż do
        # pierwszego otwarcia okna Ustawień - closeEvent() (minimize_to_tray)
        # i inne miejsca w GUI odwołujące się do ustawień nie miały do nich
        # dostępu od startu aplikacji.
        self.gui.settings = self.settings
        
        # Podłącz sygnały
        self.connect_signals()
        
        # Przywróć sesję
        self.load_from_temp_file()
        
        # Pokaż okno
        self.gui.showMaximized()
        
        # Inicjalizuj domyślne parametry Argon2 w rejestrze jeśli nie istnieją
        self.init_argon_params()

        # HOTFIX: autozapis sesji działał wcześniej TYLKO przy wyjściu przez
        # menu "Plik -> Zakończ" (on_exit wołało save_to_temp_file() raz).
        # "O programie" obiecuje "w tle automatycznie tworzone są zaszyfrowane
        # kopie zapasowe (snapshoty) aktualnej sesji" - dodajemy okresowy
        # zapis, żeby to było prawdą, a nie tylko przy zamknięciu programu.
        self.autosave_timer = QTimer()
        self.autosave_timer.setInterval(60 * 1000)  # co 60 sekund
        self.autosave_timer.timeout.connect(self.save_to_temp_file)
        self.autosave_timer.start()
    
    def _set_current_file(self, file_path):
        """Ustawia aktualnie otwarty plik i synchronizuje go z GUI.

        HOTFIX: self.current_file (na poziomie aplikacji) i self.gui.current_file
        (czytane przez SafePadGUI.update_label()/update_language() do
        wyświetlenia nazwy pliku) nigdy nie były synchronizowane - main.py
        ustawiał tylko swoje self.current_file, więc etykieta pliku w oknie
        zawsze pokazywała "brak pliku", niezależnie od tego, co faktycznie
        było otwarte/zapisane."""
        self.current_file = file_path
        self.gui.current_file = file_path

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
          sc(self.gui.save_as_vault_action.triggered, self.save_note_as_vault)
          sc(self.gui.import_as_vault_action.triggered, self.import_file_as_vault)
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
      # HOTFIX: wcześniej to była pusta gałąź (`pass`) - kliknięcie "Pokaż"
      # lub "Zakończ" w menu traya, czy dwuklik na ikonie traya, nie robiły
      # absolutnie nic. ui.py teraz emituje realne sygnały Qt dla tych
      # zdarzeń (patrz SafePadGUI.tray_show_requested/tray_exit_requested/
      # close_requested) - podłączamy je tutaj do rzeczywistej logiki
      # aplikacji.
      if hasattr(self.gui, 'tray_icon') and self.gui.tray_icon:
          sc(self.gui.tray_show_requested, self.show_normal)
          sc(self.gui.tray_exit_requested, self.on_exit)
          sc(self.gui.close_requested, self.on_exit)
    
    def init_argon_params(self):
        """Inicjalizuje domyślne parametry Argon2 w rejestrze"""
        for level, params in Registryconf.DEFAULT_ARGON_PARAMS.items():
            # Sprawdź czy istnieją, jeśli nie - zapisz
            existing = Registryconf.load_argon_conf(level)
            if existing == Registryconf.DEFAULT_ARGON_PARAMS.get(level):
                Registryconf.save_argon_conf(level, params)

    def refresh_after_language_change(self):
        """Odświeża całe GUI po zmianie języka.

        HOTFIX: wcześniej istniała tylko change_language(language_code), którą
        miało wywoływać menu "Język" (self.gui.language_actions) - menu, które
        nigdzie nie było tworzone, więc ta ścieżka była martwym kodem. Jedynym
        realnym sposobem zmiany języka jest zakładka Język w SettingsDialog,
        która SAMA zapisuje nowy język (LanguageManager.save_language()) i
        zwraca flagę "language_changed" w get_settings(). Ta metoda zajmuje się
        wyłącznie odświeżeniem GUI (tekst, etykieta pliku, sygnały) - bez
        ponownego zapisywania języka, żeby nie duplikować logiki z dialogu."""
        current_text = self.gui.text_edit.toPlainText()
        current_file = self.current_file

        self.gui.update_language()

        self.gui.text_edit.setPlainText(current_text)
        self._set_current_file(current_file)
        self.gui.update_label()

        # HOTFIX (patrz też _safe_connect): update_language() odtwarza menu i
        # toolbar, więc trzeba podłączyć sygnały do nowych obiektów akcji.
        self.connect_signals()

        self.gui.update_status(f"Język zmieniony na {LanguageManager().get_language_name()}")
    
    # ------------------------- Operacje na plikach -------------------------
    
    def new_file(self):
        self.gui.text_edit.clear()
        self._set_current_file(None)
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
            self._set_current_file(file_path)
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
            # HOTFIX: current_file był ustawiany PRZED zapisem - jeśli
            # użytkownik anulował okno hasła w _save_current_file (co
            # zwraca False i niczego nie zapisuje), aplikacja i tak
            # zostawała w stanie "plik otwarty" dla pliku, który nigdy nie
            # powstał. Ustawiamy current_file tylko po potwierdzonym
            # sukcesie zapisu.
            if self._save_current_file(file_path):
                self._set_current_file(file_path)
                self.gui.update_label()
    
    def _prompt_new_password(self, title="Nowe hasło", label="Hasło:"):
        """Pyta o nowe hasło + potwierdzenie, waliduje wg wymagań z ustawień.

        Wspólna logika wyciągnięta z _save_current_file/encrypt_folder, żeby
        nie duplikować jej po trzeci raz w metodach związanych z sejfem.
        Zwraca hasło (str) albo None, jeśli użytkownik anulował/hasła się
        nie zgadzają/nie spełniają wymagań (w tych ostatnich dwóch
        przypadkach komunikat błędu jest już wyświetlony).
        """
        pwd, ok = QInputDialog.getText(
            self.gui, title, label, QLineEdit.EchoMode.Password
        )
        if not ok or not pwd:
            return None

        is_valid, errors = check_password_requirements(pwd, self.settings)
        if not is_valid:
            QMessageBox.critical(
                self.gui, "Hasło nie spełnia wymagań",
                "Hasło nie spełnia skonfigurowanych wymagań bezpieczeństwa:\n\n"
                + "\n".join(f"• {e}" for e in errors)
            )
            return None

        confirm, ok = QInputDialog.getText(
            self.gui, "Potwierdź hasło", "Powtórz hasło:", QLineEdit.EchoMode.Password
        )
        if not ok or pwd != confirm:
            QMessageBox.critical(self.gui, "Błąd", "Hasła nie są identyczne!")
            return None

        return pwd

    def _write_vault_atomically(self, vault_path, crypto, password, entries):
        """Zapisuje sejf przez plik tymczasowy + os.replace(), żeby błąd w
        trakcie zapisu (brak miejsca na dysku, awaria zasilania) nie
        zostawił pliku sejfu w połowie nadpisanym - ważniejsze niż przy
        pojedynczej notatce, bo sejf może zawierać wiele wpisów naraz."""
        vault_bytes = VaultFormat.to_bytes(crypto, password, entries)
        tmp_path = vault_path + ".tmp"
        with open(tmp_path, 'wb') as f:
            f.write(vault_bytes)
        os.replace(tmp_path, vault_path)

    def _pick_vault_save_path(self, caption):
        """QFileDialog.getSaveFileName z wyłączonym natywnym 'czy nadpisać?'
        - sami dopytujemy jasno, czy chodzi o DOPISANIE wpisu do istniejącego
        sejfu, bo natywny prompt ('Nadpisać?') sugerowałby wymazanie
        istniejących wpisów, czego tu nigdy nie robimy."""
        vault_path, _ = QFileDialog.getSaveFileName(
            self.gui, caption, "",
            "SafePad Vault (*.spvault);;All Files (*.*)",
            options=QFileDialog.Option.DontConfirmOverwrite
        )
        if not vault_path:
            return None
        if not vault_path.endswith('.spvault'):
            vault_path += '.spvault'
        return vault_path

    def save_note_as_vault(self):
        """Zapisuje aktualnie edytowaną notatkę jako wpis w sejfie wielu
        notatek (.spvault) - nowym albo istniejącym."""
        text = self.gui.text_edit.toPlainText()
        if not text.strip():
            QMessageBox.warning(
                self.gui, "Pusta notatka",
                "Notatka jest pusta - nie ma czego zapisać jako sejf."
            )
            return

        vault_path = self._pick_vault_save_path("Zapisz jako sejf")
        if not vault_path:
            return

        default_title = os.path.splitext(os.path.basename(self.current_file))[0] \
            if self.current_file else "Notatka"
        title, ok = QInputDialog.getText(
            self.gui, "Nazwa wpisu", "Podaj nazwę wpisu w sejfie:",
            text=default_title
        )
        if not ok:
            return
        title = title.strip() or default_title

        entries = {}
        file_exists = os.path.exists(vault_path)

        if file_exists:
            # Sejf już istnieje - dopisujemy nowy wpis, nie nadpisujemy go.
            # Hasło musi być tym samym, którym jest zaszyfrowany cały sejf.
            reply = QMessageBox.question(
                self.gui, "Sejf już istnieje",
                f"Plik '{os.path.basename(vault_path)}' już istnieje jako sejf.\n\n"
                "Dopisać tę notatkę jako nowy wpis do istniejącego sejfu?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply != QMessageBox.StandardButton.Yes:
                return

            password, ok = QInputDialog.getText(
                self.gui, "Hasło sejfu",
                f"Podaj hasło do sejfu '{os.path.basename(vault_path)}':",
                QLineEdit.EchoMode.Password
            )
            if not ok or not password:
                return

            try:
                with open(vault_path, 'rb') as f:
                    existing_data = f.read()
                entries = VaultFormat.from_bytes(self.crypto, password, existing_data)
            except Exception as e:
                QMessageBox.critical(
                    self.gui, "Błąd",
                    f"Nie udało się otworzyć istniejącego sejfu "
                    f"(złe hasło lub uszkodzony plik).\n\n{e}"
                )
                return
        else:
            password = self._prompt_new_password(
                title="Nowe hasło sejfu", label="Ustaw hasło dla nowego sejfu:"
            )
            if password is None:
                return

        entry_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        entries[entry_id] = {
            "title": title,
            "content": text,
            "created_at": now,
            "modified_at": now,
        }

        try:
            self._write_vault_atomically(vault_path, self.crypto, password, entries)
        except Exception as e:
            QMessageBox.critical(self.gui, "Błąd zapisu", f"Nie udało się zapisać sejfu:\n\n{e}")
            return

        self.gui.update_status(
            f"Zapisano jako sejf: {os.path.basename(vault_path)} (wpis: {title})"
        )

    def import_file_as_vault(self):
        """Importuje istniejącą notatkę .sscr jako nowy wpis w sejfie
        (nowym albo istniejącym)."""
        source_path, _ = QFileDialog.getOpenFileName(
            self.gui, "Wybierz notatkę do zaimportowania", "",
            "SafePad Files (*.sscr);;All Files (*.*)"
        )
        if not source_path:
            return

        source_password, ok = QInputDialog.getText(
            self.gui, "Hasło notatki",
            f"Podaj hasło do '{os.path.basename(source_path)}':",
            QLineEdit.EchoMode.Password
        )
        if not ok or not source_password:
            return

        try:
            with open(source_path, 'rb') as f:
                encrypted_data = f.read()
            decrypted_data = self.crypto.decrypt_data(source_password, encrypted_data)
            content = decrypted_data.decode('utf-8')
        except Exception as e:
            QMessageBox.critical(self.gui, "Błąd", f"Nieprawidłowe hasło lub plik uszkodzony.\n\n{e}")
            return

        vault_path = self._pick_vault_save_path(
            "Zaimportuj jako sejf (wybierz nowy lub istniejący plik sejfu)"
        )
        if not vault_path:
            return

        default_title = os.path.splitext(os.path.basename(source_path))[0]
        title, ok = QInputDialog.getText(
            self.gui, "Nazwa wpisu", "Nazwa wpisu w sejfie:", text=default_title
        )
        if not ok:
            return
        title = title.strip() or default_title

        entries = {}
        file_exists = os.path.exists(vault_path)

        if file_exists:
            vault_password, ok = QInputDialog.getText(
                self.gui, "Hasło sejfu",
                f"Podaj hasło do sejfu '{os.path.basename(vault_path)}':",
                QLineEdit.EchoMode.Password
            )
            if not ok or not vault_password:
                return
            try:
                with open(vault_path, 'rb') as f:
                    existing_data = f.read()
                entries = VaultFormat.from_bytes(self.crypto, vault_password, existing_data)
            except Exception as e:
                QMessageBox.critical(
                    self.gui, "Błąd",
                    f"Nie udało się otworzyć sejfu (złe hasło lub uszkodzony plik).\n\n{e}"
                )
                return
        else:
            vault_password = self._prompt_new_password(
                title="Nowe hasło sejfu", label="Ustaw hasło dla nowego sejfu:"
            )
            if vault_password is None:
                return

        entry_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        entries[entry_id] = {
            "title": title,
            "content": content,
            "created_at": now,
            "modified_at": now,
        }

        try:
            self._write_vault_atomically(vault_path, self.crypto, vault_password, entries)
        except Exception as e:
            QMessageBox.critical(self.gui, "Błąd zapisu", f"Nie udało się zapisać sejfu:\n\n{e}")
            return

        self.gui.update_status(
            f"Zaimportowano '{os.path.basename(source_path)}' do sejfu "
            f"{os.path.basename(vault_path)} (wpis: {title})"
        )

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
            # HOTFIX (KRYTYCZNE): wcześniej ta metoda usuwała
            # output_path/output_folder niezależnie od tego, czy operacja to
            # szyfrowanie czy DESZYFROWANIE. Dla FolderEncryptWorker
            # output_path to nowo tworzony plik .enc - bezpiecznie go
            # usunąć przy anulowaniu. Ale dla FolderDecryptWorker
            # output_folder to ISTNIEJĄCY folder użytkownika (ten sam, który
            # user_confirmed nadpisać) - _extract_zip celowo nie dotyka go,
            # dopóki wypakowywanie nie powiedzie się w 100% (rozpakowuje do
            # osobnego staging-dir i podmienia folder na końcu). Usuwanie
            # output_folder tutaj niszczyło dane użytkownika, mimo że nic
            # jeszcze nie zdążyło ich zastąpić - anulowanie deszyfrowania
            # kasowało oryginalny, nietknięty folder.
            is_decrypt = isinstance(self.crypto_worker, FolderDecryptWorker)
            fresh_output_path = None if is_decrypt else getattr(self.crypto_worker, 'output_path', None)

            self.crypto_worker.request_cancel()

            # HOTFIX: self.crypto_worker.wait() blokował całą pętlę zdarzeń
            # Qt (zamrożone okno) aż do zakończenia bieżącego chunku, co przy
            # dużych CHUNK_SIZE mogło trwać dziesiątki sekund. Czekamy przez
            # lokalny QEventLoop odpytywany krótkim QTimer-em, żeby GUI
            # zostało responsywne w czasie oczekiwania na bezpieczne
            # zatrzymanie się wątku. UWAGA: nie można tu użyć sygnału
            # crypto_worker.finished/error jako warunku zakończenia - obie
            # klasy workerów DEKLARUJĄ WŁASNE sygnały o tych nazwach
            # (finished/error = pyqtSignal(str)), które przesłaniają wbudowany
            # sygnał QThread "wątek faktycznie się zakończył", a na ścieżce
            # anulowania (_WorkerCancelled) żaden z tych własnych sygnałów
            # nie jest emitowany - czekanie na nie zawiesiłoby się w
            # nieskończoność. Odpytujemy więc isRunning() bezpośrednio.
            from PyQt6.QtCore import QEventLoop, QTimer
            if self.crypto_worker.isRunning():
                wait_loop = QEventLoop()
                poll_timer = QTimer()
                poll_timer.setInterval(50)

                def _check_still_running():
                    if not self.crypto_worker.isRunning():
                        poll_timer.stop()
                        wait_loop.quit()

                poll_timer.timeout.connect(_check_still_running)
                poll_timer.start()
                wait_loop.exec()
            self.crypto_worker.wait()  # domknięcie - powinno już być zakończone

            self.progress.close()
            
            try:
                if fresh_output_path and os.path.isfile(fresh_output_path):
                    secure_delete(fresh_output_path)
                elif fresh_output_path and os.path.isdir(fresh_output_path):
                    shutil.rmtree(fresh_output_path, ignore_errors=True)
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

                # HOTFIX: po udanym przywróceniu usuwamy plik backupu - był
                # zostawiany na zawsze w %TEMP%, mimo że jego zawartość
                # została już skonsumowana (a autozapis i tak nadpisze go
                # nową kopią przy kolejnym tick-u).
                secure_delete(temp_file)
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

        # HOTFIX: self.gui.settings nigdy nie było aktualizowane - GUI (w tym
        # closeEvent(), które sprawdza "minimize_to_tray") wciąż widziało
        # ustawienia domyślne z __init__ ({}), niezależnie od tego, co
        # użytkownik zapisał w oknie Ustawień.
        self.gui.settings = new_settings
        
        # Aktualizuj szyfrowanie z nowym poziomem
        level = new_settings.get("encryption_level", "medium")
        self.crypto = EncryptionCEO(level)
        
        # Jeśli hasło do backupów zostało zmienione, przeładuj je
        if new_settings.get("backup_password_changed"):
            self.load_backup_password()

        # HOTFIX: SettingsDialog.get_settings() zwracał flagę
        # "language_changed", ale nikt jej dotąd nie odczytywał - zmiana
        # języka w oknie Ustawień była zapisywana do rejestru, ale GUI nie
        # było odświeżane, więc efekt było widać dopiero po restarcie apki.
        if new_settings.get("language_changed"):
            self.refresh_after_language_change()
        
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