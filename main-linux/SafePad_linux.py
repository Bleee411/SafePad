##########################################################
#                                                        # 
#           Program oraz kod autorstwa Szofer            #
#            Licencja: MIT License                       #
#                                                        #
##########################################################

import sys
import os
import json
import time
import hashlib
import base64
import tempfile
import shutil
from io import BytesIO
from threading import Thread
from packaging.version import parse
from PyQt6.QtCore import (Qt, QThread, pyqtSignal, QSize, QTimer, pyqtSlot, QUrl, 
                          QByteArray, QBuffer, QIODevice)
from PyQt6.QtGui import (QAction, QIcon, QPalette, QColor, QFont, QTextCursor, QFontDatabase, 
                         QPixmap, QKeySequence, QImage, QTextImageFormat, QTextDocument)
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QTextEdit, QLabel, QToolBar, QStatusBar, QMenuBar, QMenu,
                            QDialog, QTabWidget, QFormLayout, QCheckBox, QSpinBox,
                            QPushButton, QProgressBar, QMessageBox, QFileDialog,
                            QDialogButtonBox, QFrame, QScrollArea, QLineEdit, 
                            QRadioButton, QButtonGroup, QProgressDialog, QInputDialog,
                            QSizePolicy, QGridLayout, QGroupBox)
import requests
import webbrowser
import subprocess
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
from pyserpent import Serpent
from encryption_options import EncryptionHandler, ENCRYPTION_VERSION
from folder_encryption_decryption import FolderCrypto

try:
    import argon2
except ImportError:
    argon2 = None 

try:
    from migration_tool import MigrationTool  
except ImportError:
    MigrationTool = None

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    from pyupdater.client import Client, ClientConfig
    PYUPDATER_AVAILABLE = True
except ImportError:
    PYUPDATER_AVAILABLE = False

class SafePadApp(QMainWindow):
    APP_VERSION = "2.0.1"
    AUTHOR = "Szofer"

    CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".config", "SafePad")
    if not os.path.exists(CONFIG_DIR):
        os.makedirs(CONFIG_DIR, mode=0o700)
        
    CONFIG_FILE = os.path.join(CONFIG_DIR, 'config.json')
    REMIND_FILE = os.path.join(CONFIG_DIR, 'remind_later.json')

    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_TIME = 300  

    def __init__(self):
        super().__init__()
        self.password = None
        self.salt = None
        self.login_attempts = 0
        self.locked_until = 0
        self.is_dark_mode = True
        self.current_theme = "dark"
        self.image_references = []
        self.current_file = None
        
        self.settings = self.load_settings()
        self.load_bruteforce_protection()
        self.initialize_password_requirements()
        
        self.setup_linux_gui()
        self.apply_amber_night_theme()
        self.init_updater() 
        if self.update_client:
             QTimer.singleShot(5000, lambda: self.check_for_updates(silent=True))

    def setup_linux_gui(self):
        """Initialize optimized Linux GUI components"""
        self.setWindowTitle(f"SafePad {self.APP_VERSION}")
        self.setGeometry(100, 100, 1200, 800)
        
        # Set window properties for Linux
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # File label
        self.file_label = QLabel("Brak otwartego pliku")
        self.file_label.setStyleSheet("""
            QLabel {
                background-color: #3C3C3C;
                color: #FAFAFA;
                padding: 8px;
                border-bottom: 1px solid #555555;
                font-weight: bold;
                font-family: 'Noto Sans', 'DejaVu Sans', 'Arial', sans-serif;
            }
        """)
        self.file_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(self.file_label)
        
        # Text editor
        self.text_edit = QTextEdit()
        
        welcome_text = (
            "Witaj w SafePad 2.0!\n\n"  
            "Użyj Plik -> Nowy (Ctrl+N), aby rozpocząć pisanie,\n"
            "lub Plik -> Odszyfruj (Ctrl+O), aby otworzyć istniejący plik."
        )
        self.text_edit.setPlaceholderText(welcome_text)
        self.text_edit.setAlignment(Qt.AlignmentFlag.AlignLeft) 
        self.text_edit.setStyleSheet("""
        QTextEdit {
            background-color: #3C3C3C;
            color: #FAFAFA;
            border: none;
            font-family: 'Noto Sans Mono', 'DejaVu Sans Mono', 'Monospace', 'Courier New';
            font-size: 13px;
            font-weight: 400;
            selection-background-color: #FFC107;
            selection-color: #000000;
            line-height: 1.3;
            padding: 10px;
        }
        QTextEdit::placeholder {
            color: #888888;
            font-weight: 400;
            font-style: italic;
        } 
        """)
        main_layout.addWidget(self.text_edit)
        
        # Create toolbar at the BOTTOM
        self.create_linux_toolbar()
        main_layout.addWidget(self.toolbar)
        
        # Create status bar
        self.create_linux_statusbar()
        
        # Create menu bar
        self.create_linux_menubar()

    def create_linux_menubar(self):
        """Create Linux-optimized menu bar"""
        menubar = self.menuBar()
        menubar.setNativeMenuBar(True)  # Use system menu bar on Linux
        
        # File menu
        file_menu = menubar.addMenu("Plik")
        
        new_action = QAction("Nowy", self)
        new_action.setShortcut("Ctrl+N")
        new_action.triggered.connect(self.new_file)
        file_menu.addAction(new_action)
        
        open_action = QAction("Odszyfruj...", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self.open_file)
        file_menu.addAction(open_action)
        
        save_action = QAction("Zaszyfruj...", self)
        save_action.setShortcut("Ctrl+S")
        save_action.triggered.connect(self.save_as_file)
        file_menu.addAction(save_action)
        
        file_menu.addSeparator()
        
        read_only_action = QAction("Tryb tylko do odczytu", self)
        read_only_action.setCheckable(True)
        read_only_action.triggered.connect(self.toggle_read_only)
        file_menu.addAction(read_only_action)
        
        file_menu.addSeparator()
        
        encrypt_folder_action = QAction("Zaszyfruj folder...", self)
        encrypt_folder_action.triggered.connect(self.initiate_folder_encryption)
        file_menu.addAction(encrypt_folder_action)
        
        decrypt_folder_action = QAction("Odszyfruj folder...", self)
        decrypt_folder_action.triggered.connect(self.decrypt_folder)
        file_menu.addAction(decrypt_folder_action)
        
        file_menu.addSeparator()
        
        migrate_action = QAction("Migruj stare pliki...", self)
        migrate_action.triggered.connect(self.migrate_old_files)
        file_menu.addAction(migrate_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Zakończ", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.on_exit)
        file_menu.addAction(exit_action)
        
        # Edit menu
        edit_menu = menubar.addMenu("Edycja")
        
        undo_action = QAction("Cofnij", self)
        undo_action.setShortcut("Ctrl+Z")
        undo_action.triggered.connect(self.text_edit.undo)
        edit_menu.addAction(undo_action)
        
        redo_action = QAction("Ponów", self)
        redo_action.setShortcut("Ctrl+Y")
        redo_action.triggered.connect(self.text_edit.redo)
        edit_menu.addAction(redo_action)
        
        edit_menu.addSeparator()
        
        cut_action = QAction("Wytnij", self)
        cut_action.setShortcut("Ctrl+X")
        cut_action.triggered.connect(self.text_edit.cut)
        edit_menu.addAction(cut_action)
        
        copy_action = QAction("Kopiuj", self)
        copy_action.setShortcut("Ctrl+C")
        copy_action.triggered.connect(self.text_edit.copy)
        edit_menu.addAction(copy_action)
        
        paste_action = QAction("Wklej", self)
        paste_action.setShortcut("Ctrl+V")
        paste_action.triggered.connect(self.text_edit.paste)
        edit_menu.addAction(paste_action)
        
        edit_menu.addSeparator()
        
        select_all_action = QAction("Zaznacz wszystko", self)
        select_all_action.setShortcut("Ctrl+A")
        select_all_action.triggered.connect(self.text_edit.selectAll)
        edit_menu.addAction(select_all_action)
        
        # View menu
        view_menu = menubar.addMenu("Widok")
        
        zoom_in_action = QAction("Powiększ", self)
        zoom_in_action.setShortcut("Ctrl++")
        zoom_in_action.triggered.connect(self.zoom_in)
        view_menu.addAction(zoom_in_action)
        
        zoom_out_action = QAction("Pomniejsz", self)
        zoom_out_action.setShortcut("Ctrl+-")
        zoom_out_action.triggered.connect(self.zoom_out)
        view_menu.addAction(zoom_out_action)
        
        reset_zoom_action = QAction("Resetuj powiększenie", self)
        reset_zoom_action.setShortcut("Ctrl+0")
        reset_zoom_action.triggered.connect(self.reset_zoom)
        view_menu.addAction(reset_zoom_action)
        
        # Settings menu
        settings_menu = menubar.addMenu("Ustawienia")
        
        settings_panel_action = QAction("Panel ustawień", self)
        settings_panel_action.setShortcut("Ctrl+,")
        settings_panel_action.triggered.connect(self.open_settings_window)
        settings_menu.addAction(settings_panel_action)
        
        # Help menu
        help_menu = menubar.addMenu("Pomoc")
        
        about_action = QAction("O programie", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
        update_action = QAction("Sprawdź aktualizacje", self)
        update_action.triggered.connect(lambda: self.check_for_updates(silent=False))
        help_menu.addAction(update_action)
        
        change_password_action = QAction("Zmień hasło", self)
        change_password_action.triggered.connect(self.change_password)
        help_menu.addAction(change_password_action)

    def create_linux_toolbar(self):
        """Create Linux-optimized toolbar at the BOTTOM"""
        self.toolbar = QToolBar()
        self.toolbar.setIconSize(QSize(24, 24))
        self.toolbar.setMovable(False)
        
        buttons = [
            ("Nowy", self.new_file, "📄"),
            ("Otwórz", self.open_file, "📂"),
            ("Zapisz", self.save_file, "💾"),
            ("", None, ""), 
            ("Wytnij", self.text_edit.cut, "✂️"),
            ("Kopiuj", self.text_edit.copy, "📋"),
            ("Wklej", self.text_edit.paste, "📌"),
            ("", None, ""), 
            ("Dodaj zdjęcie", self._insert_image_from_dialog, "🖼️"),
            ("", None, ""),  
            ("Szyfruj", self.save_as_file, "🔒"),
            ("Odszyfruj", self.open_file, "🔓")
        ]
        
        for text, command, icon in buttons:
            if not text:  
                sep = QFrame()
                sep.setFrameShape(QFrame.Shape.VLine)
                sep.setFrameShadow(QFrame.Shadow.Sunken)
                sep.setStyleSheet("background-color: #555555;")
                sep.setMaximumWidth(2)
                self.toolbar.addWidget(sep)
                continue
                
            btn = QPushButton(f"{icon} {text}")
            btn.clicked.connect(command)
            btn.setStyleSheet("""
             QPushButton {
             background-color: #3C3C3C;
             color: #FAFAFA;
             border: none;
             padding: 8px 12px;
             margin: 2px;
             border-radius: 3px;
             font-weight: normal;
             font-family: 'DejaVu Sans', 'Sans Serif';
             }
             QPushButton:hover {
              background-color: #FFC107;
             color: #000000;
             font-weight: normal;
              }
             QPushButton:pressed {
             background-color: #FFB300;
             font-weight: normal;
             }
            """)
            self.toolbar.addWidget(btn)

    def create_linux_statusbar(self):
        """Create Linux-optimized status bar"""
        self.status_bar = QStatusBar()
        
        self.status_label = QLabel("Gotowy")
        self.line_col_label = QLabel("Linia: 1, Kolumna: 1")
        self.zoom_label = QLabel("100%")
        
        self.status_label.setStyleSheet("color: #FAFAFA; font-weight: normal;")
        self.line_col_label.setStyleSheet("color: #FAFAFA; font-weight: normal;")
        self.zoom_label.setStyleSheet("color: #FAFAFA; font-weight: normal;")
        
        self.status_bar.addWidget(self.status_label, 1)
        self.status_bar.addPermanentWidget(self.line_col_label)
        self.status_bar.addPermanentWidget(self.zoom_label)
        
        self.setStatusBar(self.status_bar)
        
        # Connect signals
        self.text_edit.cursorPositionChanged.connect(self.update_line_col)

    def apply_amber_night_theme(self):
        """Apply Amber Night theme optimized for Linux"""
        self.setStyleSheet("""
            * {
                font-family: 'Noto Sans', 'DejaVu Sans', 'Liberation Sans', 'Arial', sans-serif;
                font-size: 11px;
                font-weight: 400;
            }
            QMainWindow {
                background-color: #2B2B2B;
                color: #FAFAFA;
            }
            QMenuBar {
                background-color: #2B2B2B;
                color: #FAFAFA;
                border-bottom: 1px solid #555555;
                font-weight: 500;
                padding: 2px;
            }
            QMenuBar::item {
                background-color: transparent;
                padding: 6px 10px;
                font-weight: 500;
                border-radius: 3px;
            }
            QMenuBar::item:selected {
                background-color: #FFC107;
                color: #000000;
                font-weight: 600;
            }
            QMenu {
                background-color: #3C3C3C;
                color: #FAFAFA;
                border: 1px solid #555555;
                font-weight: 400;
                padding: 5px;
            }
            QMenu::item {
                padding: 6px 24px;
                font-weight: 400;
                border-radius: 2px;
            }
            QMenu::item:selected {
                background-color: #FFC107;
                color: #000000;
                font-weight: 500;
            }
            QStatusBar {
                background-color: #2B2B2B;
                color: #FAFAFA;
                border-top: 1px solid #555555;
                font-weight: 400;
            }
            QToolBar {
                background-color: #3C3C3C;
                border: none;
                spacing: 3px;
                padding: 3px;
                border-top: 1px solid #555555;
            }
            QMessageBox {
                background-color: #2B2B2B;
                color: #FAFAFA;
            }
            QMessageBox QLabel {
                color: #FAFAFA;
                font-weight: 400;
            }
            QMessageBox QPushButton {
                background-color: #3C3C3C;
                color: #FAFAFA;
                padding: 6px 16px;
                border: none;
                border-radius: 4px;
                font-weight: 500;
                min-width: 70px;
            }
            QMessageBox QPushButton:hover {
                background-color: #FFC107;
                color: #000000;
                font-weight: 500;
            }
            QLabel {
                font-weight: 400;
            }
            QPushButton {
                font-weight: 500;
            }
        """)

    def zoom_in(self):
        """Zoom in text"""
        font = self.text_edit.font()
        size = font.pointSize()
        if size < 30:
            font.setPointSize(size + 1)
            self.text_edit.setFont(font)
            self.update_zoom_label(size + 1)

    def zoom_out(self):
        """Zoom out text"""
        font = self.text_edit.font()
        size = font.pointSize()
        if size > 6:
            font.setPointSize(size - 1)
            self.text_edit.setFont(font)
            self.update_zoom_label(size - 1)

    def reset_zoom(self):
        """Reset zoom to default"""
        font = self.text_edit.font()
        font.setPointSize(10)
        self.text_edit.setFont(font)
        self.update_zoom_label(10)

    def update_zoom_label(self, size):
        """Update zoom percentage in status bar"""
        percentage = int((size / 10.0) * 100)
        self.zoom_label.setText(f"{percentage}%")

    def update_line_col(self):
        """Update line and column information in status bar"""
        if self.text_edit.alignment() == Qt.AlignmentFlag.AlignCenter:
            self.text_edit.setAlignment(Qt.AlignmentFlag.AlignLeft)
            
        cursor = self.text_edit.textCursor()
        line = cursor.blockNumber() + 1
        col = cursor.columnNumber() + 1
        self.line_col_label.setText(f"Linia: {line}, Kolumna: {col}")
        
    def update_status(self, message, is_error=False):
        """Update status bar message"""
        color = "#FF5555" if is_error else "#FAFAFA"
        self.status_label.setText(message)
        self.status_label.setStyleSheet(f"color: {color};")
        
    def update_label(self):
        """Update file info label"""
        if hasattr(self, 'current_file') and self.current_file:
            self.file_label.setText(f"Plik: {os.path.basename(self.current_file)}")
        else:
            self.file_label.setText("Brak otwartego pliku")

    def open_settings_window(self):
        """Settings window with PyQt6"""
        dialog = SettingsDialog(self, self.settings)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.settings = dialog.get_settings()
            self.save_settings()
            self.initialize_password_requirements()

    def prompt_password(self):
        """Prompt for password with PyQt6"""
        password, ok = QInputDialog.getText(
            self, "SafePad - Hasło", "Podaj hasło:", 
            QLineEdit.EchoMode.Password
        )
        return password if ok else None

    def _prompt_new_password_with_verification(self):
        """Prompt for new password with verification"""
        while True:
            password, ok = QInputDialog.getText(
                self, "SafePad - Nowe hasło", "Wpisz hasło do zaszyfrowania pliku:",
                QLineEdit.EchoMode.Password
            )
            if not ok or not password:
                return None
                
            if len(password) < self.password_min_length:
                QMessageBox.critical(
                    self, "SafePad - Błąd", 
                    f"Hasło jest za krótkie. Wymagana minimalna długość to {self.password_min_length} znaków."
                )
                continue
                
            confirm_password, ok = QInputDialog.getText(
                self, "SafePad - Potwierdź hasło", "Wpisz hasło ponownie, aby potwierdzić:",
                QLineEdit.EchoMode.Password
            )
            if not ok:
                return None
                
            if password == confirm_password:
                return password
            else:
                QMessageBox.critical(self, "SafePad - Błąd", "Hasła nie są identyczne. Spróbuj ponownie.")

    def show_file_encryption_success(self, file_path, duration, file_size):
        """Show success dialog after file encryption"""
        msg = QMessageBox(self)
        msg.setWindowTitle("SafePad - Szyfrowanie zakończone")
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setText("Plik został pomyślnie zaszyfrowany!")
        
        duration_str = f"{duration:.2f} sek"
        size_str = self._format_file_size(file_size)
        
        msg.setInformativeText(
            f"Lokalizacja: {file_path}\n"
            f"Rozmiar: {size_str} | Czas operacji: {duration_str}"
        )
        
        msg.addButton("OK", QMessageBox.ButtonRole.AcceptRole)
        open_folder_btn = msg.addButton("Otwórz folder", QMessageBox.ButtonRole.ActionRole)
        
        msg.exec()
        
        if msg.clickedButton() == open_folder_btn:
            try:
                subprocess.run(['xdg-open', os.path.dirname(file_path)], check=False)
            except:
                QMessageBox.information(self, "SafePad - Informacja", f"Folder: {os.path.dirname(file_path)}")

    def create_progress_window(self, title):
        """Create progress window for long operations"""
        progress_dialog = QProgressDialog(title, "Anuluj", 0, 100, self)
        progress_dialog.setWindowModality(Qt.WindowModality.WindowModal)
        progress_dialog.setAutoClose(True)
        progress_dialog.setAutoReset(True)
        progress_dialog.setStyleSheet("""
            QProgressDialog {
                background-color: #2B2B2B;
                color: #FAFAFA;
            }
            QProgressBar {
                border: 1px solid #555555;
                border-radius: 3px;
                text-align: center;
                background-color: #3C3C3C;
            }
            QProgressBar::chunk {
                background-color: #FFC107;
            }
        """)
        return progress_dialog

    
    def _center_window(self, window, width, height):
        """Centers a Toplevel window on the screen."""
        screen_width = window.winfo_screenwidth()
        screen_height = window.winfo_screenheight()
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        window.geometry(f"{width}x{height}+{x}+{y}")
    
    def _format_file_size(self, num_bytes):
        """Formatuje rozmiar pliku w B, KB, MB, GB."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if abs(num_bytes) < 1024.0:
                return f"{num_bytes:3.1f} {unit}"
            num_bytes /= 1024.0
        return f"{num_bytes:.1f} TB"
        
    def initialize_password_requirements(self):
        """Set default password requirements"""
        self.password_min_length = self.settings["password_min_length"]
        self.password_require_upper = self.settings["password_require_upper"]
        self.password_require_lower = self.settings["password_require_lower"] 
        self.password_require_number = self.settings["password_require_number"]
        self.password_require_special = self.settings["password_require_special"]
        self.encryption_level = self.settings["encryption_level"]   
        current_argon2_params = self.settings["argon2_params"][self.encryption_level]
        self.encryption_handler = EncryptionHandler(current_argon2_params)

    def new_file(self):
        """Create new empty file"""
        self.text_edit.clear()
        self.text_edit.setAlignment(Qt.AlignmentFlag.AlignLeft)
        self.current_file = None
        self.password = None
        self.update_label()
        self.update_status("Nowy plik utworzony")
        self.reset_zoom()
    
    def open_file(self, file_path=None):
        """Otwiera i odszyfrowuje plik (tylko nowy format v2.0)."""
        if self.is_account_locked():
            self.show_lockout_message()
            return

        if not file_path: 
            file_path, _ = QFileDialog.getOpenFileName(
                self, "SafePad - Otwórz plik", "",
                "SafePad Files (*.sscr);;All Files (*.*)"
            )
            if not file_path:
                return

        password = self.prompt_password()
        if not password:
            return 

        try:
            with open(file_path, "rb") as f:
                file_data = f.read()

            if len(file_data) < 32 or file_data[:4].decode('utf-8', errors='ignore') != ENCRYPTION_VERSION:
                raise ValueError("Ten plik nie jest w obsługiwanym formacie (v2.0) lub jest uszkodzony. Użyj narzędzia do migracji dla starszych plików.")

            self._open_modern_file(file_path, password, file_data)

        except ValueError as e:
            self.handle_login_failure()
            
            if not self.is_account_locked():
                remaining = self.MAX_LOGIN_ATTEMPTS - self.login_attempts
                QMessageBox.critical(
                    self, "SafePad - Błąd odszyfrowywania", 
                    f"Nieprawidłowe hasło lub plik jest uszkodzony.\n\nPozostało prób: {remaining}"
                )

    def _open_modern_file(self, file_path, password, file_data):
        """Otwiera plik zaszyfrowany w nowym formacie AEAD (v2.0)."""
        try:
            salt = file_data[4:20]
            nonce = file_data[20:32]
            encrypted_data = file_data[32:]

            key = self.generate_key(password, salt)
            decrypted_data = self.encryption_handler.decrypt_data(key, nonce, encrypted_data)
            
            self.password = password

            self._deserialize_content(decrypted_data)
            self.text_edit.setAlignment(Qt.AlignmentFlag.AlignLeft)

            self.current_file = file_path
            self.update_label()
            self.update_status(f"Otwarto: {os.path.basename(file_path)}")
            self.reset_login_attempts()
            self.text_edit.document().setModified(False)
        except Exception as e:
            raise ValueError(f"Nieprawidłowe hasło lub plik jest uszkodzony. Szczegóły: {e}")
    
    def save_file(self):
        """Save current file"""
        if hasattr(self, 'current_file') and self.current_file:
            self._save_current_file(self.current_file) 
        else:
            self.save_as_file()

    def save_as_file(self):
        """Save file with new name"""
        try:
            file_path, _ = QFileDialog.getSaveFileName(
                self, "SafePad - Zapisz plik jako", "",
                "SafePad Files (*.sscr);;All Files (*.*)"
            )
            
            if file_path:
                self.current_file = file_path
                self._save_current_file(file_path)
                
        except Exception as e:
            QMessageBox.critical(self, "SafePad - Błąd", f"Nie udało się zapisać pliku: {str(e)}")

    def _save_current_file(self, file_path, migrate=False):
        try:
            if not self.password or migrate:
                password = self._prompt_new_password_with_verification()
                if not password:
                    raise ValueError("Hasło jest wymagane!")
                self.password = password

            start_time = time.time() 
            
            self.salt = os.urandom(self.encryption_handler.get_salt_size())
            nonce = os.urandom(self.encryption_handler.get_nonce_size())
    
            data_to_encrypt = self._serialize_content()
            
            self.key = self.generate_key(self.password, self.salt)
            encrypted_data = self.encryption_handler.encrypt_data(self.key, nonce, data_to_encrypt)

            with open(file_path, "wb") as f:
                f.write(ENCRYPTION_VERSION.encode('utf-8'))
                f.write(self.salt)
                f.write(nonce)
                f.write(encrypted_data)
            
            duration = time.time() - start_time
            file_size = os.path.getsize(file_path)

            self.update_status(f"Zapisano: {os.path.basename(file_path)}")
            self.text_edit.document().setModified(False)
            
            self.show_file_encryption_success(file_path, duration, file_size)
            
        except Exception as e:
            QMessageBox.critical(self, "SafePad - Błąd", f"Nie udało się zapisać pliku: {str(e)}")

    def generate_key(self, password, salt):
        """Generate encryption key using Argon2"""
        return self.encryption_handler.generate_key(password, salt)

    def toggle_read_only(self):
        """Toggle read-only mode"""
        is_read_only = self.text_edit.isReadOnly()
        self.text_edit.setReadOnly(not is_read_only)
        status = "Tylko do odczytu" if not is_read_only else "Edycja włączona"
        self.update_status(status)


    def toggle_notifications(self):
        """Toggle notifications on/off"""
        self.settings["notifications"] = not self.settings.get("notifications", True)
        self.save_settings()
        status = "Powiadomienia wyłączone" if not self.settings["notifications"] else "Powiadomienia włączone"
        self.update_status(status)

    def change_password(self):
        """Change encryption password"""
        if not hasattr(self, 'current_file') or not self.current_file:
            QMessageBox.information(self, "SafePad - Informacja", "Najpierw otwórz plik, którego hasło chcesz zmienić.")
            return
            
        old_password, ok = QInputDialog.getText(
            self, "SafePad - Zmiana hasła", "Podaj stare hasło:", 
            QLineEdit.EchoMode.Password
        )
        if not ok or not old_password:
            return
            
        try:
            with open(self.current_file, "rb") as f:
                file_data = f.read()
                
            if file_data[:4].decode('utf-8') == ENCRYPTION_VERSION:
                salt = file_data[4:20]
                nonce = file_data[20:32]
                encrypted_data = file_data[32:]
                
                key = self.generate_key(old_password, salt)
                self.encryption_handler.decrypt_data(key, nonce, encrypted_data)
            else:
                salt, iv, encrypted_data = file_data[:16], file_data[16:32], file_data[32:]
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                    backend=default_backend()
                )
                key = kdf.derive(old_password.encode())
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
                unpadder = PKCS7(128).unpadder()
                unpadder.update(decrypted_padded) + unpadder.finalize()
                
        except Exception:
            QMessageBox.critical(self, "SafePad - Błąd", "Nieprawidłowe stare hasło.")
            return
            
        new_password, ok = QInputDialog.getText(
            self, "SafePad - Zmiana hasła", "Podaj nowe hasło:", 
            QLineEdit.EchoMode.Password
        )
        if not ok or not new_password:
            return
            
        confirm_password, ok = QInputDialog.getText(
            self, "SafePad - Zmiana hasła", "Potwierdź nowe hasło:", 
            QLineEdit.EchoMode.Password
        )
        if not ok or new_password != confirm_password:
            QMessageBox.critical(self, "SafePad - Błąd", "Hasła nie są identyczne.")
            return
            
        try:
            with open(self.current_file, "rb") as f:
                file_data = f.read()
                
            if file_data[:4].decode('utf-8') == ENCRYPTION_VERSION:
                salt = file_data[4:20]
                nonce = file_data[20:32]
                encrypted_data = file_data[32:]
                
                key = self.generate_key(old_password, salt)
                decrypted_data = self.encryption_handler.decrypt_data(key, nonce, encrypted_data)
            else:
                salt, iv, encrypted_data = file_data[:16], file_data[16:32], file_data[32:]
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                    backend=default_backend()
                )
                key = kdf.derive(old_password.encode())
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
                unpadder = PKCS7(128).unpadder()
                decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()
                
            new_salt = os.urandom(self.encryption_handler.get_salt_size())
            new_nonce = os.urandom(self.encryption_handler.get_nonce_size())
            new_key = self.generate_key(new_password, new_salt)
            new_encrypted_data = self.encryption_handler.encrypt_data(new_key, new_nonce, decrypted_data)
            
            with open(self.current_file, "wb") as f:
                f.write(ENCRYPTION_VERSION.encode('utf-8'))
                f.write(new_salt)
                f.write(new_nonce)
                f.write(new_encrypted_data)
                
            QMessageBox.information(self, "SafePad - Sukces", "Hasło zostało pomyślnie zmienione.")
            self.update_status("Hasło zmienione")
            
        except Exception as e:
            QMessageBox.critical(self, "SafePad - Błąd", f"Nie udało się zmienić hasła: {e}")

    def show_about(self):
        """Show about dialog"""
        about_text = f"""SafePad {self.APP_VERSION}

Bezpieczny edytor tekstu z szyfrowaniem AES-GCM i Argon2ID.

Autor: {self.AUTHOR}
Format szyfrowania: {ENCRYPTION_VERSION}
Poziom bezpieczeństwa: {self.encryption_level.capitalize()}

Funkcje:
- Szyfrowanie plików i folderów
- Ochrona przed atakami brute force
- Wsparcie dla obrazów
- Motywy jasny/ciemny
- Weryfikacja integralności danych (AEAD)"""
        
        QMessageBox.about(self, "SafePad - O programie", about_text)


    def check_for_updates(self, silent=True):
        """Uruchamia wątek sprawdzania aktualizacji."""
        if not self.update_client:
            if not silent:
                QMessageBox.critical(self, "SafePad - Błąd", "Moduł aktualizacji (PyUpdater) nie jest poprawnie skonfigurowany lub zainstalowany.")
            return

        self.update_worker = UpdateCheckWorker(self.update_client, silent)
        self.update_worker.status.connect(self.update_status)
        self.update_worker.update_ready.connect(self.show_update_notification)
        self.update_worker.no_update_found.connect(self.on_no_update_found)
        self.update_worker.error.connect(self.on_update_error)
        self.update_worker.start()

    @pyqtSlot()
    def show_update_notification(self):
        """Pokazuje powiadomienie o gotowej aktualizacji na pasku statusu."""
        self.update_status("Dostępna nowa wersja!")
        
        self.restart_btn = QPushButton("🎁 Uruchom ponownie, aby zaktualizować")
        self.restart_btn.setStyleSheet("""
            QPushButton { 
                background-color: #FFC107; color: #000000; 
                font-weight: bold; padding: 2px 5px; border-radius: 3px;
            }
            QPushButton:hover { background-color: #FFB300; }
        """)
        self.restart_btn.clicked.connect(self.apply_update_and_restart)
        
        self.status_bar.addPermanentWidget(self.restart_btn)

    @pyqtSlot()
    def on_no_update_found(self):
        """Pokazuje okno 'Brak aktualizacji' (tylko przy sprawdzaniu ręcznym)."""
        QMessageBox.information(self, "SafePad - Aktualizacje", "Masz najnowszą wersję programu.")

    @pyqtSlot(str)
    def on_update_error(self, error_msg):
        """Pokazuje okno błędu (tylko przy sprawdzaniu ręcznym)."""
        QMessageBox.critical(self, "SafePad - Błąd aktualizacji", error_msg)

    @pyqtSlot()
    def apply_update_and_restart(self):
        """Uruchamia proces podmiany plików i restartu aplikacji."""
        self.update_status("Instalowanie aktualizacji...")
        
        if self.update_client:
            self.update_client.restart()
        
        self.close() 

    def on_exit(self):
        """Handle application exit"""
        if self.text_edit.document().isModified():
            result = QMessageBox.question(
                self, "SafePad", "Zapisać zmiany przed zamknięciem?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel
            )
            
            if result == QMessageBox.StandardButton.Cancel:
                return
            if result == QMessageBox.StandardButton.Yes:
                self.save_file()
        
        self.save_settings()
        QApplication.quit()

    def load_settings(self):
        """Load application settings"""
        default_settings = {
            "dark_mode": False,
            "password_min_length": 8,
            "password_require_upper": True,
            "password_require_lower": True,
            "password_require_number": True,
            "password_require_special": False,
            "notifications": True,
            "remind_later": False,
            "encryption_level": "normal",
            "argon2_params": {
                "low": {"m": 16 * 1024, "t": 2, "p": 1},
                "normal": {"m": 64 * 1024, "t": 3, "p": 2},
                "high": {"m": 512 * 1024, "t": 4, "p": 4}
            }
        }
        
        try:
            if os.path.exists(self.CONFIG_FILE):
                with open(self.CONFIG_FILE, "r") as f:
                    loaded = json.load(f)
                    # Merge with defaults
                    return {**default_settings, **loaded}
        except:
            pass
            
        return default_settings

    def save_settings(self):
        """Save application settings"""
        try:
            with open(self.CONFIG_FILE, "w") as f:
                json.dump(self.settings, f, indent=2)
        except:
            pass

    def load_bruteforce_protection(self):
        """Wczytuje dane ochrony brute-force z pliku konfiguracyjnego."""
        self.login_attempts = 0
        self.locked_until = 0
        
        try:
            protection_file = os.path.join(self.CONFIG_DIR, "bruteforce_protection.json")
            if os.path.exists(protection_file):
                with open(protection_file, "r") as f:
                    data = json.load(f)
                    self.login_attempts = data.get("login_attempts", 0)
                    self.locked_until = data.get("locked_until", 0)
        except Exception as e:
            print(f"Błąd odczytu pliku ochrony brute-force: {e}")
            self.login_attempts = 0
            self.locked_until = 0

    def save_bruteforce_protection(self):
        """Zapisuje dane ochrony brute-force do pliku konfiguracyjnego."""
        try:
            protection_file = os.path.join(self.CONFIG_DIR, "bruteforce_protection.json")
            data = {
                "login_attempts": self.login_attempts,
                "locked_until": self.locked_until
            }
            with open(protection_file, "w") as f:
                json.dump(data, f)
        except Exception as e:
            print(f"Nie udało się zapisać pliku ochrony brute-force: {e}")

    def is_account_locked(self):
        """Check if account is temporarily locked"""
        if self.locked_until > time.time():
            return True
        elif self.locked_until > 0:
            self.login_attempts = 0
            self.locked_until = 0
            self.save_bruteforce_protection()
        return False

    def handle_login_failure(self):
        """Handle failed login attempt"""
        self.login_attempts += 1
        self.save_bruteforce_protection()
        
        if self.login_attempts >= self.MAX_LOGIN_ATTEMPTS:
            self.locked_until = time.time() + self.LOCKOUT_TIME
            self.save_bruteforce_protection()
            self.show_lockout_message()

    def reset_login_attempts(self):
        """Reset login attempts on successful login"""
        self.login_attempts = 0
        self.locked_until = 0
        self.save_bruteforce_protection()

    def show_lockout_message(self):
        """Show account lockout message"""
        remaining = int(self.locked_until - time.time())
        minutes = remaining // 60
        seconds = remaining % 60
        QMessageBox.critical(
            self, "SafePad - Konto zablokowane", 
            f"Zbyt wiele nieudanych prób logowania. Konto zablokowane na {minutes} minut i {seconds} sekund."
        )

    def save_security_settings(self):
        """Save security settings (excluding Argon2 params)"""
        try:
            self.password_min_length = self.min_length_var.get()
            self.password_require_upper = self.require_upper_var.get()
            self.password_require_lower = self.require_lower_var.get()
            self.password_require_number = self.require_number_var.get()
            self.password_require_special = self.require_special_var.get()
            self.encryption_level = self.enc_level_var.get()
            
            self.settings.update({
                "password_min_length": self.password_min_length,
                "password_require_upper": self.password_require_upper,
                "password_require_lower": self.password_require_lower,
                "password_require_number": self.password_require_number,
                "password_require_special": self.password_require_special,
                "encryption_level": self.encryption_level
            })
            
        except Exception as e:
            print(f"Błąd w save_security_settings: {e}")


    def initiate_folder_encryption(self):
        """Initiate folder encryption process"""
        folder_path = QFileDialog.getExistingDirectory(self, "SafePad - Wybierz folder do zaszyfrowania")
        if not folder_path:
            return
            
        output_path, _ = QFileDialog.getSaveFileName(
            self, "SafePad - Zapisz zaszyfrowany folder jako", "",
            "Zaszyfrowane foldery (*.enc);;Wszystkie pliki (*.*)"
        )
        if not output_path:
            return
            
        password = self.prompt_password()
        if not password:
            return
            
        self.progress_dialog = self.create_progress_window("Szyfrowanie folderu...")
        
        current_argon2_params = self.settings["argon2_params"][self.encryption_level]

        self.crypto_worker = FolderCryptoWorker(
            "encrypt", password, current_argon2_params, folder_path, output_path, self
        )
        
        self.crypto_worker.status.connect(self.progress_dialog.setLabelText)
        self.crypto_worker.progress.connect(self.progress_dialog.setValue)
        self.crypto_worker.finished.connect(self.on_crypto_finished)
        self.crypto_worker.error.connect(self.on_crypto_error)
        self.progress_dialog.canceled.connect(self.cancel_crypto_worker)
        
        self.crypto_worker.start() 
        self.progress_dialog.exec()
        
    def decrypt_folder(self):
        """Initiate folder decryption process"""
        encrypted_path, _ = QFileDialog.getOpenFileName(
            self, "SafePad - Wybierz zaszyfrowany folder", "",
            "Zaszyfrowane foldery (*.enc);;Wszystkie pliki (*.*)"
        )
        if not encrypted_path:
            return
            
        output_folder = QFileDialog.getExistingDirectory(self, "SafePad - Wybierz folder docelowy do odszyfrowania")
        if not output_folder:
            return
            
        password = self.prompt_password()
        if not password:
            return
            
        self.progress_dialog = self.create_progress_window("Odszyfrowywanie folderu...")

        current_argon2_params = self.settings["argon2_params"][self.encryption_level]
        
        self.crypto_worker = FolderCryptoWorker(
            "decrypt", password, current_argon2_params, encrypted_path, output_folder, self
        )
        
        self.crypto_worker.status.connect(self.progress_dialog.setLabelText)
        self.crypto_worker.progress.connect(self.progress_dialog.setValue)
        self.crypto_worker.finished.connect(self.on_crypto_finished)
        self.crypto_worker.error.connect(self.on_crypto_error)
        self.progress_dialog.canceled.connect(self.cancel_crypto_worker)

        self.crypto_worker.start() 
        self.progress_dialog.exec() 
        
    @pyqtSlot()
    def cancel_crypto_worker(self):
        """Slot do anulowania operacji (przycisk Anuluj na pasku postępu)."""
        if hasattr(self, 'crypto_worker') and self.crypto_worker.isRunning():
            self.crypto_worker.terminate()
            self.progress_dialog.close()
            self.update_status("Operacja anulowana przez użytkownika", is_error=True)

    @pyqtSlot(str)
    def on_crypto_finished(self, success_message):
        """Slot wywoływany po pomyślnem zakończeniu pracy wątku."""
        self.progress_dialog.close()
        self.update_status(success_message)
        QMessageBox.information(self, "SafePad - Sukces", "Operacja zakończona pomyślnie.")

    @pyqtSlot(str)
    def on_crypto_error(self, error_message):
        """Slot wywoływany w przypadku błędu w wątku."""
        self.progress_dialog.close()
        self.update_status("Błąd operacji na folderze", is_error=True)
        QMessageBox.critical(self, "SafePad - Błąd", f"Wystąpił błąd: {error_message}")

    def migrate_old_files(self):
        """Otwiera dedykowane narzędzie do migracji plików."""
        if MigrationTool is None:
            QMessageBox.critical(
                self, "SafePad - Błąd", 
                "Nie można załadować narzędzia migracyjnego (brak pliku migration_tool.py)."
            )
            return
            
        try:
            subprocess.Popen([sys.executable, "migration_tool.py"])
            
        except Exception as e:
            QMessageBox.critical(self, "SafePad - Błąd", f"Nie udało się uruchomić narzędzia migracyjnego: {e}")

    def _serialize_content(self):
        """Serialize text content and images from QJsonTextEdit into a JSON structure."""
        content_data = []
        doc = self.text_edit.document()
        
        block = doc.begin()
        while block.isValid():
            iterator = block.begin()
            while not iterator.atEnd():
                fragment = iterator.fragment()
                if fragment.isValid():
                    if fragment.charFormat().isImageFormat():
                        img_format = fragment.charFormat().toImageFormat()
                        img_name = img_format.name()
                        
                        img_variant = doc.resource(QTextDocument.ResourceType.ImageResource, QUrl(img_name))
                        
                        q_image = QImage(img_variant)
                        
                        if q_image.isNull():
                            print(f"Nie można pobrać obrazu z zasobu: {img_name}")
                            continue

                        byte_array = QByteArray()
                        buffer = QBuffer(byte_array)
                        buffer.open(QIODevice.OpenModeFlag.WriteOnly)
                        q_image.save(buffer, "PNG") 
                        
                        img_base64 = base64.b64encode(byte_array.data()).decode('utf-8')
                        
                        content_data.append({
                            "type": "image",
                            "data": img_base64,
                            "width": img_format.width(),
                            "height": img_format.height()
                        })
                    else:
                        text = fragment.text()
                        if text:
                            content_data.append({
                                "type": "text",
                                "content": text
                            })
                iterator += 1
            
            if block.next().isValid():
                 content_data.append({"type": "text", "content": "\n"})
                 
            block = block.next()
            
        return json.dumps(content_data).encode('utf-8')

    def _deserialize_content(self, data):
        """Deserialize content from JSON into QTextEdit."""
        self.text_edit.clear()
        self.image_references.clear() 
        
        try:
            content_data = json.loads(data.decode('utf-8'))
        except json.JSONDecodeError:
            self.text_edit.setPlainText(data.decode('utf-8', 'ignore'))
            return
            
        cursor = self.text_edit.textCursor()
        doc = self.text_edit.document()
        
        for item in content_data:
            item_type = item.get("type")
            
            if item_type == "text":
                cursor.insertText(item.get("content", ""))
                
            elif item_type == "image":
                try:
                    img_base64 = item.get("data")
                    img_data = base64.b64decode(img_base64)
                    
                    q_image = QImage()
                    q_image.loadFromData(img_data, "PNG")

                    if q_image.isNull():
                        continue 
                        
                    image_name = f"image_{time.time()}.png"
                    doc.addResource(QTextDocument.ResourceType.ImageResource, QUrl(image_name), q_image)
                    
                    image_format = QTextImageFormat()
                    image_format.setName(image_name)
                    image_format.setWidth(item.get("width", q_image.width()))
                    image_format.setHeight(item.get("height", q_image.height()))
                    
                    cursor.insertImage(image_format)
                
                except Exception as e:
                    print(f"Błąd ładowania obrazu z JSON: {e}")
                    cursor.insertText("[BŁĄD ŁADOWANIA OBRAZU]")

        self.text_edit.setAlignment(Qt.AlignmentFlag.AlignLeft)

    def _insert_image_from_dialog(self):
        """Insert image from file dialog (PyQt6 version)"""
        if not HAS_PIL:
            QMessageBox.critical(self, "SafePad - Błąd", "Wymagana biblioteka Pillow do obsługi obrazów.")
            return

        file_path, _ = QFileDialog.getOpenFileName(
            self, "SafePad - Wybierz obraz", "",
            "Obrazy (*.png *.jpg *.jpeg *.bmp *.gif);;Wszystkie pliki (*.*)"
        )

        if file_path:
            try:
                image = Image.open(file_path)
                
                max_width = 600
                if image.width > max_width:
                    ratio = max_width / float(image.width)
                    height = int(float(image.height) * ratio)
                    image = image.resize((max_width, height), Image.Resampling.LANCZOS)
                
                buffer = BytesIO()
                image.save(buffer, "PNG") 
                
                img_data = buffer.getvalue()
                q_image = QImage()
                q_image.loadFromData(img_data, "PNG")

                if q_image.isNull():
                    raise ValueError("Nie udało się przekonwertować obrazu PIL na QImage")

                cursor = self.text_edit.textCursor()
                doc = self.text_edit.document()
                image_name = f"image_{time.time()}.png"
                doc.addResource(QTextDocument.ResourceType.ImageResource, QUrl(image_name), q_image)
                
                image_format = QTextImageFormat()
                image_format.setName(image_name)
                image_format.setWidth(q_image.width())
                image_format.setHeight(q_image.height())
                
                cursor.insertImage(image_format)
                
            except Exception as e:
                QMessageBox.critical(self, "SafePad - Błąd", f"Nie udało się wczytać obrazu: {e}")
                
                
    def init_updater(self):
        """Inicjalizuje klienta PyUpdater."""
        self.update_client = None
        if not PYUPDATER_AVAILABLE:
            print("OSTRZEŻENIE: PyUpdater nie jest zainstalowany. Aktualizacje są wyłączone.")
            return

        try:
            import client_config 
            
            self.update_client = Client(client_config)
            
            self.update_client.refresh() 
        except ImportError:
            print("BŁĄD: Nie można znaleźć pliku client_config.py. Uruchom 'pyupdater init'.")
            self.update_client = None
        except Exception as e:
            print(f"BŁĄD: Nie udało się zainicjować klienta aktualizacji: {e}")
            self.update_client = None
                
class UpdateCheckWorker(QThread):
    """
    Sprawdza i pobiera aktualizacje w tle, używając PyUpdater.
    """
    status = pyqtSignal(str)          
    update_ready = pyqtSignal()      
    no_update_found = pyqtSignal()    
    error = pyqtSignal(str)          

    def __init__(self, client, silent=True, parent=None):
        super().__init__(parent)
        self.client = client
        self.silent = silent

    def run(self):
        try:
            self.status.emit("Sprawdzanie aktualizacji...")
            
            update_available = self.client.check_for_update()
            
            if update_available:
                self.status.emit("Pobieranie nowej wersji...")
                
                if self.client.download_update():
                    self.status.emit("Aktualizacja gotowa do instalacji.")
                    self.update_ready.emit()
                else:
                    if not self.silent:
                        self.error.emit("Pobieranie nie powiodło się lub weryfikacja podpisu była negatywna.")
            else:
                self.status.emit("Brak nowych aktualizacji.")
                if not self.silent:
                    self.no_update_found.emit()

        except Exception as e:
            if not self.silent:
                self.error.emit(f"Błąd połączenia z serwerem: {e}")
                
class BenchmarkWorker(QThread):
    """
    Uruchamia benchmark Argon2 w osobnym wątku, aby nie blokować UI.
    Wysyła sygnały o postępie i wynikach.
    """
    status = pyqtSignal(str)
    progress = pyqtSignal(int)
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.TARGET_TIME = 2.0  
        self.password = b"benchmark-password"
        self.salt = os.urandom(16)

    def run(self):
        try:
            parallelism = os.cpu_count() or 1
            best_mem = 64 * 1024
            time_cost = 1

            self.status.emit("Testowanie kosztu pamięci...")
            mem = 64 * 1024
            mem_step = 0
            while True:
                mem_step += 1
                self.status.emit(f"Testuję: {mem // 1024} MB pamięci...")
                self.progress.emit(min(mem_step * 5, 50)) 
                
                try:
                    start_time = time.time()
                    argon2.low_level.hash_secret_raw(
                        secret=self.password, salt=self.salt, time_cost=time_cost, memory_cost=mem,
                        parallelism=parallelism, hash_len=32, type=argon2.Type.ID
                    )
                    elapsed = time.time() - start_time

                    if elapsed > self.TARGET_TIME:
                        best_mem = mem // 2 
                        break
                    
                    if mem >= 8 * 1024 * 1024: 
                         best_mem = mem
                         break

                    mem *= 2

                except argon2.exceptions.HashingError:
                    best_mem = mem // 2
                    break
            
            self.status.emit("Dostosowywanie kosztu czasu...")
            self.progress.emit(50)
            time_cost = 1
            
            while True:
                self.status.emit(f"Testuję: {time_cost} iteracji...")
                self.progress.emit(min(50 + (time_cost * 5), 99)) 
                
                start_time = time.time()
                argon2.low_level.hash_secret_raw(
                    secret=self.password, salt=self.salt, time_cost=time_cost, memory_cost=best_mem,
                    parallelism=parallelism, hash_len=32, type=argon2.Type.ID
                )
                elapsed = time.time() - start_time

                if elapsed > self.TARGET_TIME:
                    time_cost = max(1, time_cost - 1) 
                    break
                
                if time_cost >= 20: 
                    break
                
                time_cost += 1

            self.progress.emit(100)
            self.finished.emit({
                "m": best_mem,
                "t": time_cost,
                "p": parallelism
            })

        except Exception as e:
            self.error.emit(f"Wystąpił nieoczekiwany błąd: {e}")
            
class FolderCryptoWorker(QThread):
    """
    Uruchamia szyfrowanie/deszyfrowanie folderu w osobnym wątku.
    """
    status = pyqtSignal(str)
    progress = pyqtSignal(int)
    finished = pyqtSignal(str) 
    error = pyqtSignal(str)    

    def __init__(self, mode, password, argon2_params, path1, path2, parent=None):
        super().__init__(parent)
        self.mode = mode 
        self.password = password
        self.argon2_params = argon2_params
        self.path1 = path1 
        self.path2 = path2 

    def run(self):
        try:
            crypto = FolderCrypto(self.password, self.argon2_params)
            
            progress_callback = lambda p: self.progress.emit(int(p))
            status_callback = lambda s: self.status.emit(s)

            if self.mode == "encrypt":
                status_callback("Inicjalizowanie szyfrowania...")
                
                crypto.encrypt_folder(
                    self.path1, self.path2, 
                    progress_callback=progress_callback, 
                    status_callback=status_callback
                )
                self.finished.emit(f"Folder zaszyfrowany: {os.path.basename(self.path2)}")
            
            elif self.mode == "decrypt":
                status_callback("Inicjalizowanie deszyfrowania...")
                
                crypto.decrypt_folder(
                    self.path1, self.path2, 
                    progress_callback=progress_callback, 
                    status_callback=status_callback
                )
                self.finished.emit(f"Folder odszyfrowany: {os.path.basename(self.path1)}")

        except Exception as e:
            self.error.emit(str(e)) 

class SettingsDialog(QDialog):
    """Settings dialog with PyQt6"""
    
    def __init__(self, parent=None, settings=None):
        super().__init__(parent)
        self.parent = parent
        self.settings = settings or {}
        self.setup_ui()
        
    def setup_ui(self):
        self.setWindowTitle("SafePad - Ustawienia")
        self.setFixedSize(700, 600)
        
        layout = QVBoxLayout(self)
        
        # Tab widget
        tab_widget = QTabWidget()
        tab_widget.setTabPosition(QTabWidget.TabPosition.West)
        
        # Security tab
        security_tab = QWidget()
        self.setup_security_tab(security_tab)
        tab_widget.addTab(security_tab, "🛡️ Bezpieczeństwo")
        
        # Argon2 tab
        argon2_tab = QWidget()
        self.setup_argon2_tab(argon2_tab)
        tab_widget.addTab(argon2_tab, "⚙️ Argon2")
        
        # Appearance tab
        appearance_tab = QWidget()
        self.setup_appearance_tab(appearance_tab)
        tab_widget.addTab(appearance_tab, "🎨 Wygląd")
        
        layout.addWidget(tab_widget)
        
        # Buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | 
            QDialogButtonBox.StandardButton.Cancel
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
        self.apply_theme()
        
    def setup_security_tab(self, tab):
      layout = QVBoxLayout(tab)
    
      # Password requirements
      requirements_group = QGroupBox("Wymagania hasła")
      requirements_layout = QFormLayout(requirements_group)
    
      # Min password length
      self.min_length_spin = QSpinBox()
      self.min_length_spin.setRange(4, 32)
      self.min_length_spin.setValue(self.settings.get("password_min_length", 8))
    
      requirements_layout.addRow("Minimalna długość hasła:", self.min_length_spin)
    
      # Password requirements checkboxes
      self.require_upper_cb = QCheckBox("Wymagaj wielkich liter (A-Z)")
      self.require_upper_cb.setChecked(self.settings.get("password_require_upper", True))
      requirements_layout.addRow(self.require_upper_cb)
    
      self.require_lower_cb = QCheckBox("Wymagaj małych liter (a-z)")
      self.require_lower_cb.setChecked(self.settings.get("password_require_lower", True))
      requirements_layout.addRow(self.require_lower_cb)
    
      self.require_number_cb = QCheckBox("Wymagaj cyfr (0-9)")
      self.require_number_cb.setChecked(self.settings.get("password_require_number", True))
      requirements_layout.addRow(self.require_number_cb)
    
      self.require_special_cb = QCheckBox("Wymagaj znaków specjalnych (!@#...)")
      self.require_special_cb.setChecked(self.settings.get("password_require_special", False))
      requirements_layout.addRow(self.require_special_cb)
    
      layout.addWidget(requirements_group)
    
      # Encryption level
      encryption_group = QGroupBox("Poziom szyfrowania")
      encryption_layout = QVBoxLayout(encryption_group)
    
      self.enc_level_group = QButtonGroup(self)
      levels = [
        ("Niski (AES-GCM-256)", "low"),
        ("Normalny (AES-GCM-256)", "normal"), 
        ("Wysoki (AES-GCM-256)", "high")
      ]
    
      current_level = self.settings.get("encryption_level", "normal")
      for text, level in levels:
          radio = QRadioButton(text)
          radio.setChecked(level == current_level)
          self.enc_level_group.addButton(radio)
          encryption_layout.addWidget(radio)
          setattr(self, f"enc_level_{level}_radio", radio)
    
      layout.addWidget(encryption_group)
      layout.addStretch()
        
    def setup_argon2_tab(self, tab):
        layout = QVBoxLayout(tab)
        
        # Get current encryption level
        current_level = self.settings.get("encryption_level", "normal")
        argon2_params = self.settings.get("argon2_params", {}).get(current_level, {
            "m": 64 * 1024, "t": 3, "p": 2
        })
        
        params_group = QGroupBox(f"Parametry Argon2 dla poziomu: {current_level.capitalize()}")
        params_layout = QFormLayout(params_group)
        
        # Memory cost
        self.argon2_mem_spin = QSpinBox()
        self.argon2_mem_spin.setRange(16, 8192)
        self.argon2_mem_spin.setValue(argon2_params.get("m", 64 * 1024) // 1024)
        self.argon2_mem_spin.setSuffix(" MB")
        params_layout.addRow("Koszt pamięci:", self.argon2_mem_spin)
        
        # Time cost
        self.argon2_time_spin = QSpinBox()
        self.argon2_time_spin.setRange(1, 20)
        self.argon2_time_spin.setValue(argon2_params.get("t", 3))
        self.argon2_time_spin.setSuffix(" iteracji")
        params_layout.addRow("Koszt czasu:", self.argon2_time_spin)
        
        # Parallelism
        self.argon2_para_spin = QSpinBox()
        self.argon2_para_spin.setRange(1, os.cpu_count() or 1)
        self.argon2_para_spin.setValue(argon2_params.get("p", 2))
        self.argon2_para_spin.setSuffix(" wątków")
        params_layout.addRow("Równoległość:", self.argon2_para_spin)
        
        layout.addWidget(params_group)
        
        # Benchmark button
        benchmark_btn = QPushButton("Uruchom Benchmark")
        benchmark_btn.setStyleSheet("""
            QPushButton {
                background-color: #FFC107;
                color: #000000;
                border: none;
                padding: 8px 15px;
                border-radius: 3px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #FFB300;
            }
        """)
        benchmark_btn.clicked.connect(self.run_benchmark)
        layout.addWidget(benchmark_btn)
        
        # Warning label
        warning_label = QLabel(
            "UWAGA: Zmiana tych parametrów sprawi, że pliki zaszyfrowane na starych ustawieniach "
            "PRZESTANĄ SIĘ OTWIERAĆ! Zmieniaj je tylko, jeśli konfigurujesz aplikację po raz pierwszy."
        )
        warning_label.setWordWrap(True)
        warning_label.setStyleSheet("color: #FF5555; font-weight: bold;")
        layout.addWidget(warning_label)
        
        layout.addStretch()
        
    def setup_appearance_tab(self, tab):
        layout = QVBoxLayout(tab)
        
        # Appearance settings
        appearance_group = QGroupBox("Ustawienia wyglądu")
        appearance_layout = QVBoxLayout(appearance_group)
        
        self.system_theme_cb = QCheckBox("Użyj motywu systemowego")
        self.system_theme_cb.setChecked(False)
        appearance_layout.addWidget(self.system_theme_cb)
        
        self.dark_mode_cb = QCheckBox("Tryb ciemny")
        self.dark_mode_cb.setChecked(self.settings.get("dark_mode", True))
        appearance_layout.addWidget(self.dark_mode_cb)
        
        self.notifications_cb = QCheckBox("Włącz powiadomienia")
        self.notifications_cb.setChecked(self.settings.get("notifications", True))
        appearance_layout.addWidget(self.notifications_cb)
        
        layout.addWidget(appearance_group)
        layout.addStretch()
        
    def run_benchmark(self):
        """Uruchamia benchmark Argon2 w wątku roboczym."""
        if argon2 is None:
            QMessageBox.critical(self, "SafePad - Błąd", 
                "Biblioteka 'argon2-cffi' nie jest zainstalowana.\nZainstaluj ją komendą: pip install argon2-cffi")
            return
            
        self.progress_dialog = QProgressDialog("Uruchamianie benchmarku Argon2...", "Anuluj", 0, 100, self)
        self.progress_dialog.setWindowModality(Qt.WindowModality.WindowModal)
        self.progress_dialog.setAutoClose(False) 
        self.progress_dialog.setAutoReset(False)
        
        self.benchmark_worker = BenchmarkWorker(self)
        
        self.benchmark_worker.status.connect(self.update_benchmark_status)
        self.benchmark_worker.progress.connect(self.progress_dialog.setValue)
        self.benchmark_worker.finished.connect(self.on_benchmark_finished)
        self.benchmark_worker.error.connect(self.on_benchmark_error)
        
        self.progress_dialog.canceled.connect(self.benchmark_worker.terminate) 
        
        self.benchmark_worker.start() 
        self.progress_dialog.exec()

    @pyqtSlot(str)
    def update_benchmark_status(self, status):
        """Aktualizuje tekst etykiety w oknie postępu."""
        if hasattr(self, 'progress_dialog'):
            self.progress_dialog.setLabelText(status)

    @pyqtSlot(dict)
    def on_benchmark_finished(self, results):
        """Wywoływane po pomyślnym zakończeniu benchmarku."""
        if hasattr(self, 'progress_dialog'):
            self.progress_dialog.close()
            
        self.argon2_mem_spin.setValue(results["m"] // 1024)
        self.argon2_time_spin.setValue(results["t"])
        self.argon2_para_spin.setValue(results["p"])
        
        QMessageBox.information(self, "SafePad - Benchmark Zakończony",
            f"Znaleziono optymalne ustawienia dla Twojego systemu:\n\n"
            f"Pamięć: {results['m'] // 1024} MB\n"
            f"Iteracje: {results['t']}\n"
            f"Wątki: {results['p']}\n\n"
            "Zalecane wartości zostały ustawione. Kliknij 'OK' (Zapisz), aby je zachować.")

    @pyqtSlot(str)
    def on_benchmark_error(self, error_msg):
        """Wywoływane w przypadku błędu benchmarku."""
        if hasattr(self, 'progress_dialog'):
            self.progress_dialog.close()
        QMessageBox.critical(self, "SafePad - Błąd Benchmarku", error_msg)
        
    def get_settings(self):
        """Get updated settings from dialog"""
        encryption_level = "normal"
        if hasattr(self, 'enc_level_low_radio') and self.enc_level_low_radio.isChecked():
            encryption_level = "low"
        elif hasattr(self, 'enc_level_high_radio') and self.enc_level_high_radio.isChecked():
            encryption_level = "high"
            
        argon2_params = self.settings.get("argon2_params", {
            "low": {"m": 16 * 1024, "t": 2, "p": 1},
            "normal": {"m": 64 * 1024, "t": 3, "p": 2},
            "high": {"m": 512 * 1024, "t": 4, "p": 4}
        })
        
        argon2_params[encryption_level] = {
            "m": self.argon2_mem_spin.value() * 1024,
            "t": self.argon2_time_spin.value(),
            "p": self.argon2_para_spin.value()
        }
        
        return {
            "password_min_length": self.min_length_spin.value(),
            "password_require_upper": self.require_upper_cb.isChecked(),
            "password_require_lower": self.require_lower_cb.isChecked(),
            "password_require_number": self.require_number_cb.isChecked(),
            "password_require_special": self.require_special_cb.isChecked(),
            "encryption_level": encryption_level,
            "argon2_params": argon2_params,
            "dark_mode": self.dark_mode_cb.isChecked(),
            "notifications": self.notifications_cb.isChecked(),
            "remind_later": self.settings.get("remind_later", False)
        }
        
    def apply_theme(self):
      """Apply Amber Night theme to dialog"""
      self.setStyleSheet("""
        QDialog {
            background-color: #2B2B2B;
            color: #FAFAFA;
            font-family: 'Noto Sans', 'DejaVu Sans', 'Arial', sans-serif;
            font-size: 11px;
            font-weight: 400;
        }
        QTabWidget::pane {
            border: 1px solid #555555;
            background-color: #3C3C3C;
        }
        QTabBar::tab {
            background-color: #3C3C3C;
            color: #FAFAFA;
            padding: 10px 14px;
            margin: 2px;
            font-weight: 500;
            border: none;
        }
        QTabBar::tab:selected {
            background-color: #FFC107;
            color: #000000;
            font-weight: 600;
        }
        QGroupBox {
            color: #FAFAFA;
            background-color: #2B2B2B;
            border: 2px solid #555555;
            margin-top: 15px;
            padding: 15px 12px 12px 12px;
            font-weight: 600;
            font-size: 12px;
            border-radius: 6px;
        }
        QGroupBox::title {
            font-weight: 600;
            font-style: normal;
            font-family: 'Noto Sans', 'DejaVu Sans', 'Liberation Sans';
        }
        QCheckBox {
            color: #FAFAFA;
            spacing: 8px;
            font-weight: 400;
        }
        QCheckBox::indicator {
            width: 16px;
            height: 16px;
            border-radius: 3px;
        }
        QCheckBox::indicator:unchecked {
            border: 2px solid #555555;
            background-color: #3C3C3C;
        }
        QCheckBox::indicator:checked {
            border: 2px solid #FFC107;
            background-color: #FFC107;
        }
        QRadioButton {
            color: #FAFAFA;
            spacing: 8px;
            font-weight: 400;
        }
        QRadioButton::indicator {
            width: 16px;
            height: 16px;
        }
        QRadioButton::indicator:unchecked {
            border: 2px solid #555555;
            background-color: #3C3C3C;
            border-radius: 8px;
        }
        QRadioButton::indicator:checked {
            border: 2px solid #FFC107;
            background-color: #FFC107;
            border-radius: 8px;
        }
        QLabel {
            color: #FAFAFA;
            font-weight: 400;
        }
        QSpinBox {
            background-color: #3C3C3C;
            color: #FAFAFA;
            border: 2px solid #555555;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: 400;
            min-width: 80px;
        }
        QSpinBox:focus {
            border-color: #FFC107;
        }
        QPushButton {
            background-color: #3C3C3C;
            color: #FAFAFA;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            font-weight: 500;
        }
        QPushButton:hover {
            background-color: #FFC107;
            color: #000000;
        }
        QProgressDialog {
            background-color: #2B2B2B;
            color: #FAFAFA;
        }
        QProgressBar {
            border: 2px solid #555555;
            border-radius: 4px;
            text-align: center;
            background-color: #3C3C3C;
            color: #FAFAFA;
        }
        QProgressBar::chunk {
            background-color: #FFC107;
            border-radius: 2px;
        }
        QFormLayout {
            font-weight: 400;
        }
       """)

def main():
    """Main application entry point optimized for Linux"""
    app = QApplication(sys.argv)
    
    app.setApplicationName("SafePad")
    app.setApplicationVersion("2.0.1")
    app.setOrganizationName("Szofer")
    app.setDesktopFileName("safepad")
    
    app.setStyle("Fusion")
    
    app_font = QFont()
    app_font.setFamilies(["Noto Sans", "DejaVu Sans", "Liberation Sans", "Arial"])
    app_font.setPointSize(10)
    app_font.setWeight(QFont.Weight.Normal)
    app.setFont(app_font)
    
    # Set application icon
    icon_paths = [
        "/usr/share/pixmaps/safepad.png",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "safe.png"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "safe.ico"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.png"),
    ]
    
    for icon_path in icon_paths:
        if os.path.exists(icon_path):
            app.setWindowIcon(QIcon(icon_path))
            break
    else:
        pixmap = QPixmap(64, 64)
        pixmap.fill(QColor("#FFC107"))
        app.setWindowIcon(QIcon(pixmap))
    
    window = SafePadApp()
    window.show()
    
    window.showMaximized()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()