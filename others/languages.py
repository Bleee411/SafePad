import json
import os
from pathlib import Path

LANGUAGES = {
    "pl": "Polski",
    "en": "English"
}

TRANSLATIONS = {
    "pl": {
        # Menu Plik
        "menu_file": "Plik",
        "menu_new": "Nowy",
        "menu_open": "Otwórz...",
        "menu_save": "Zapisz...",
        "menu_save_as": "Zapisz jako...",
        "menu_read_only": "Tryb tylko do odczytu",
        "menu_encrypt_folder": "Zaszyfruj folder",
        "menu_decrypt_folder": "Odszyfruj folder",
        "menu_exit": "Zakończ",
        "menu_edit": "Edycja",
        "menu_undo": "Cofnij",
        "menu_redo": "Ponów",
        "menu_cut": "Wytnij",
        "menu_copy": "Kopiuj",
        "menu_paste": "Wklej",
        "menu_select_all": "Zaznacz wszystko",
        "menu_settings": "Ustawienia",
        "menu_settings_panel": "Panel ustawień",
        "menu_language": "Język",
        "menu_help": "Pomoc",
        "menu_about": "O programie",
        
        # Toolbar
        "toolbar_new": "Nowy",
        "toolbar_open": "Otwórz",
        "toolbar_save": "Zapisz",
        "toolbar_cut": "Wytnij",
        "toolbar_copy": "Kopiuj",
        "toolbar_paste": "Wklej",
        
        # Status
        "status_ready": "Gotowy",
        "status_new_file": "Nowy plik utworzony",
        "status_saved": "Zapisano: {}",
        "status_opened": "Otwarto: {}",
        "status_read_only_on": "Tryb tylko do odczytu",
        "status_read_only_off": "Edycja włączona",
        "status_session_restored": "Sesja przywrócona",
        "status_settings_saved": "Ustawienia zapisane w rejestrze",
        "status_error": "Błąd",
        "status_cancelled": "Operacja anulowana",
        "status_fullscreen_on": "Tryb pełnoekranowy (naciśnij F11 lub Esc, aby wyjść)",
        "status_fullscreen_off": "Tryb okienkowy",
        
        # Dialogs
        "dialog_open_title": "Otwórz plik",
        "dialog_open_filter": "Pliki SafePad (*.sscr);;Wszystkie pliki (*.*)",
        "dialog_save_title": "Zapisz plik jako",
        "dialog_save_filter": "Pliki SafePad (*.sscr);;Wszystkie pliki (*.*)",
        "dialog_password_title": "Hasło",
        "dialog_password_label": "Podaj hasło:",
        "dialog_new_password_title": "Nowe hasło",
        "dialog_new_password_label": "Hasło:",
        "dialog_confirm_password_title": "Potwierdź",
        "dialog_confirm_password_label": "Powtórz hasło:",
        "dialog_password_mismatch": "Hasła nie są identyczne!",
        "dialog_invalid_password": "Nieprawidłowe hasło lub plik uszkodzony.\n\n{}",
        "dialog_save_error": "Nie udało się zapisać: {}",
        
        # Folder operations
        "dialog_select_folder_encrypt": "Wybierz folder do zaszyfrowania",
        "dialog_save_encrypted": "Zapisz zaszyfrowany folder",
        "dialog_encrypt_password": "Hasło do szyfrowania folderu:",
        "dialog_select_folder_decrypt": "Wybierz zaszyfrowany folder",
        "dialog_select_output_folder": "Wybierz lokalizację dla odszyfrowanego folderu",
        "dialog_decrypt_password": "Hasło do odszyfrowania:",
        "dialog_folder_exists": "Folder '{}' już istnieje.\nCzy chcesz go nadpisać?",
        
        # Progress dialogs
        "progress_encrypt_title": "Szyfrowanie folderu",
        "progress_decrypt_title": "Odszyfrowywanie folderu",
        "progress_preparing": "Przygotowywanie...",
        "progress_packing": "Pakowanie plików...",
        "progress_encrypting": "Szyfrowanie danych...",
        "progress_decrypting": "Deszyfrowanie danych...",
        "progress_cascade": "Deszyfrowanie kaskadowe...",
        "progress_extracting": "Wypakowywanie plików...",
        "progress_cancel": "Anuluj",
        
        # Messages
        "msg_encrypt_success": "Folder zaszyfrowany: {}",
        "msg_decrypt_success": "Folder odszyfrowany do: {}",
        "msg_decrypt_complete": "Folder odszyfrowany pomyślnie!\n\n{}",
        "msg_empty_folder": "Folder jest pusty!",
        "msg_invalid_zip": "Odszyfrowane dane nie są prawidłowym archiwum ZIP",
        "msg_dangerous_path": "Wykryto niebezpieczną ścieżkę w archiwum",
        
        # Settings
        "settings_title": "Ustawienia SafePad",
        "settings_tab_security": "  🛡️ Bezpieczeństwo  ",
        "settings_tab_argon2": "  ⚙️ Argon2ID  ",
        "settings_tab_appearance": "  🎨 Wygląd  ",
        "settings_tab_backup": "  💾 Backup  ",
        "settings_tab_language": "  🌐 Język  ",
        
        # Security tab
        "security_group_password": "📝 Wymagania hasła",
        "security_min_length": "Minimalna długość hasła:",
        "security_require_upper": "Wymagaj wielkich liter (A-Z)",
        "security_require_lower": "Wymagaj małych liter (a-z)",
        "security_require_number": "Wymagaj cyfr (0-9)",
        "security_require_special": "Wymagaj znaków specjalnych (!@#...)",
        "security_group_encryption": "🔒 Poziom szyfrowania",
        "security_level_low": "🟢 Niski (szybszy, mniej pamięci)",
        "security_level_medium": "🟡 Normalny (zalecany)",
        "security_level_high": "🔴 Wysoki (podwójne szyfrowanie AES-256-GCM + Serpent-256-CBC, wolniejszy)",
        
        # Argon2 tab
        "argon2_info_title": "🔐 Co to jest Argon2ID?",
        "argon2_info_text": "Argon2ID to najnowszy algorytm wyprowadzania klucza, zwycięzca konkursu Password Hashing Competition.\n\nOptymalne parametry zależą od twojego komputera:\n• m (pamięć) - im więcej tym bezpieczniej, ale wolniej\n• t (iteracje) - liczba przejść algorytmu\n• p (wątki) - równoległość obliczeń\n\nUruchom benchmark, aby dobrać optymalne parametry dla swojego komputera!",
        "argon2_benchmark_btn": "🚀 Uruchom benchmark Argon2ID",
        "argon2_benchmark_desc": "Benchmark automatycznie dobierze parametry Argon2ID tak,\naby operacja trwała około 2 sekundy na twoim komputerze.",
        "argon2_current_params": "📊 Aktualne parametry Argon2ID",
        "argon2_memory": "💾 Pamięć (m):",
        "argon2_iterations": "🔄 Iteracje (t):",
        "argon2_threads": "🧵 Wątki (p):",
        "argon2_recommendations": "💡 Rekomendacje",
        "argon2_tips": "• Dla laptopów: użyj wyników benchmarku lub poziomu 'normal'\n• Dla komputerów stacjonarnych: możesz użyć poziomu 'high'\n• Zmiana parametrów wpływa tylko na NOWE pliki\n• Benchmark uruchom ponownie po zmianie sprzętu",
        
        # Appearance tab
        "appearance_group": "🎨 Ustawienia wyglądu",
        "appearance_dark_mode": "🌙 Tryb ciemny",
        "appearance_notifications": "🔔 Włącz powiadomienia",
        
        # Backup tab
        "backup_info_title": "💾 Backup sesji",
        "backup_info_text": "SafePad automatycznie zapisuje twoją sesję przy zamykaniu programu.\nDzięki temu nie stracisz danych nawet przy nieoczekiwanym zamknięciu.\n\nBackup jest szyfrowany hasłem. Możesz użyć domyślnego hasła lub\nustawić własne dla większego bezpieczeństwa.",
        "backup_password_group": "🔑 Hasło do backupów",
        "backup_status_custom": "✅ Status: Używasz własnego hasła do backupów",
        "backup_status_default": "ℹ️ Status: Używasz domyślnego hasła do backupów\n   (zalecane ustawienie własnego hasła)",
        "backup_status_error": "⚠️ Status: Nie można sprawdzić statusu hasła",
        "backup_new_password": "Nowe hasło:",
        "backup_confirm_password": "Potwierdź hasło:",
        "backup_save_btn": "💾 Zapisz hasło",
        "backup_reset_btn": "🔄 Przywróć domyślne",
        "backup_tips_title": "💡 Wskazówki bezpieczeństwa",
        "backup_tips": "• Użyj silnego, unikalnego hasła do backupów\n• Nie używaj tego samego hasła co do plików\n• Zapamiętaj swoje hasło - nie ma opcji odzyskiwania\n• Domyślne hasło jest bezpieczne, ale mniej prywatne\n• Backup jest zapisywany w folderze tymczasowym systemu",
        
        # Language tab
        "language_group": "🌐 Ustawienia języka",
        "language_select": "Wybierz język:",
        "language_restart_hint": "Zmiana języka wymaga ponownego uruchomienia aplikacji.",
        "language_restart_question": "Zmieniono język. Czy chcesz teraz ponownie uruchomić aplikację?",
        
        # Backup password dialogs
        "backup_warning_empty": "Uwaga",
        "backup_warning_empty_text": "Wprowadź nowe hasło!",
        "backup_error_mismatch": "Błąd",
        "backup_error_mismatch_text": "Hasła nie są identyczne!\n\nWprowadź takie same hasło w obu polach.",
        "backup_warning_weak": "Słabe hasło",
        "backup_warning_weak_text": "Hasło ma mniej niż 6 znaków. Może być słabe.\n\nCzy na pewno chcesz użyć tego hasła?",
        "backup_success": "Sukces",
        "backup_success_save": "✅ Hasło do backupów zostało zapisane!\n\nNowe hasło będzie używane przy następnym backupie sesji.\nPamiętaj, aby je zapamiętać - nie ma opcji odzyskiwania!",
        "backup_success_reset": "✅ Przywrócono domyślne hasło do backupów!\n\nBackupy będą teraz szyfrowane domyślnym hasłem.",
        "backup_reset_confirm_title": "Przywróć domyślne hasło",
        "backup_reset_confirm_text": "Czy na pewno chcesz przywrócić domyślne hasło do backupów?\n\nTwoje własne hasło zostanie usunięte.",
        
        # Benchmark
        "benchmark_title": "Benchmark Argon2ID",
        "benchmark_complete": "Benchmark zakończony",
        "benchmark_complete_text": "✨ Optymalne parametry zostały dobrane!\n\nWynik benchmarku:\n\n💾 Pamięć: {} MB\n🔄 Iteracje: {}\n🧵 Wątki: {}\n\nZalecane poziomy bezpieczeństwa:\n• 🟢 LOW:   {} MB, {} iteracji, {} wątków\n• 🟡 MEDIUM: {} MB, {} iteracji, {} wątków\n• 🔴 HIGH:  {} MB, {} iteracji, {} wątków\n\n✅ Parametry zapisano w rejestrze.",
        "benchmark_error": "Błąd benchmarku",
        "benchmark_missing_lib": "Biblioteka argon2-cffi nie jest zainstalowana.\n\nZainstaluj ją komendą:\npip install argon2-cffi\n\nBłąd: {}",
        "benchmark_start_error": "Nie udało się uruchomić benchmarku:\n{}",
        
        # About dialog
        "about_title": "O programie",
        "about_text": "SafePad {}\n\nBezpieczny edytor tekstu z szyfrowaniem AES-GCM i Argon2ID.\n\nAutor: {}\n\nFunkcje:\n- Szyfrowanie plików\n- Szyfrowanie folderów\n- Argon2ID z AES-GCM 256\n- Automatyczny backup sesji\n- Wielojęzyczność\n- Licencja: MIT",
        
        # File label
        "file_label_none": "Brak otwartego pliku",
        "file_label": "Plik: {}",
        
        # Placeholder
        "placeholder_text": "Witaj w SafePad!\n\nUżyj Plik -> Nowy (Ctrl+N), aby rozpocząć pisanie,\nlub Plik -> Otwórz (Ctrl+O), aby otworzyć istniejący plik.",
        
        # Errors
        "error_unknown": "Wystąpił nieznany błąd",
        
        # Buttons
        "btn_ok": "OK",
        "btn_cancel": "Anuluj",
        "btn_yes": "Tak",
        "btn_no": "Nie",
    },
    
    "en": {
        # File menu
        "menu_file": "File",
        "menu_new": "New",
        "menu_open": "Open...",
        "menu_save": "Save...",
        "menu_save_as": "Save as...",
        "menu_read_only": "Read-only mode",
        "menu_encrypt_folder": "Encrypt folder",
        "menu_decrypt_folder": "Decrypt folder",
        "menu_exit": "Exit",
        "menu_edit": "Edit",
        "menu_undo": "Undo",
        "menu_redo": "Redo",
        "menu_cut": "Cut",
        "menu_copy": "Copy",
        "menu_paste": "Paste",
        "menu_select_all": "Select all",
        "menu_settings": "Settings",
        "menu_settings_panel": "Settings panel",
        "menu_language": "Language",
        "menu_help": "Help",
        "menu_about": "About",
        
        # Toolbar
        "toolbar_new": "New",
        "toolbar_open": "Open",
        "toolbar_save": "Save",
        "toolbar_cut": "Cut",
        "toolbar_copy": "Copy",
        "toolbar_paste": "Paste",
        
        # Status
        "status_ready": "Ready",
        "status_new_file": "New file created",
        "status_saved": "Saved: {}",
        "status_opened": "Opened: {}",
        "status_read_only_on": "Read-only mode",
        "status_read_only_off": "Editing enabled",
        "status_session_restored": "Session restored",
        "status_settings_saved": "Settings saved in registry",
        "status_error": "Error",
        "status_cancelled": "Operation cancelled",
        "status_fullscreen_on": "Fullscreen mode (press F11 or Esc to exit)",
        "status_fullscreen_off": "Window mode",
        
        # Dialogs
        "dialog_open_title": "Open file",
        "dialog_open_filter": "SafePad Files (*.sscr);;All Files (*.*)",
        "dialog_save_title": "Save file as",
        "dialog_save_filter": "SafePad Files (*.sscr);;All Files (*.*)",
        "dialog_password_title": "Password",
        "dialog_password_label": "Enter password:",
        "dialog_new_password_title": "New password",
        "dialog_new_password_label": "Password:",
        "dialog_confirm_password_title": "Confirm",
        "dialog_confirm_password_label": "Repeat password:",
        "dialog_password_mismatch": "Passwords do not match!",
        "dialog_invalid_password": "Invalid password or corrupted file.\n\n{}",
        "dialog_save_error": "Failed to save: {}",
        
        # Folder operations
        "dialog_select_folder_encrypt": "Select folder to encrypt",
        "dialog_save_encrypted": "Save encrypted folder",
        "dialog_encrypt_password": "Password for folder encryption:",
        "dialog_select_folder_decrypt": "Select encrypted folder",
        "dialog_select_output_folder": "Select location for decrypted folder",
        "dialog_decrypt_password": "Password for decryption:",
        "dialog_folder_exists": "Folder '{}' already exists.\nDo you want to overwrite it?",
        
        # Progress dialogs
        "progress_encrypt_title": "Encrypting folder",
        "progress_decrypt_title": "Decrypting folder",
        "progress_preparing": "Preparing...",
        "progress_packing": "Packing files...",
        "progress_encrypting": "Encrypting data...",
        "progress_decrypting": "Decrypting data...",
        "progress_cascade": "Cascade decryption...",
        "progress_extracting": "Extracting files...",
        "progress_cancel": "Cancel",
        
        # Messages
        "msg_encrypt_success": "Folder encrypted: {}",
        "msg_decrypt_success": "Folder decrypted to: {}",
        "msg_decrypt_complete": "Folder decrypted successfully!\n\n{}",
        "msg_empty_folder": "Folder is empty!",
        "msg_invalid_zip": "Decrypted data is not a valid ZIP archive",
        "msg_dangerous_path": "Dangerous path detected in archive",
        
        # Settings
        "settings_title": "SafePad Settings",
        "settings_tab_security": "  🛡️ Security  ",
        "settings_tab_argon2": "  ⚙️ Argon2ID  ",
        "settings_tab_appearance": "  🎨 Appearance  ",
        "settings_tab_backup": "  💾 Backup  ",
        "settings_tab_language": "  🌐 Language  ",
        
        # Security tab
        "security_group_password": "📝 Password requirements",
        "security_min_length": "Minimum password length:",
        "security_require_upper": "Require uppercase letters (A-Z)",
        "security_require_lower": "Require lowercase letters (a-z)",
        "security_require_number": "Require numbers (0-9)",
        "security_require_special": "Require special characters (!@#...)",
        "security_group_encryption": "🔒 Encryption level",
        "security_level_low": "🟢 Low (faster, less memory)",
        "security_level_medium": "🟡 Normal (recommended)",
        "security_level_high": "🔴 High (double encryption AES-256-GCM + Serpent-256-CBC, slower)",
        
        # Argon2 tab
        "argon2_info_title": "🔐 What is Argon2ID?",
        "argon2_info_text": "Argon2ID is the latest key derivation algorithm, winner of the Password Hashing Competition.\n\nOptimal parameters depend on your computer:\n• m (memory) - more memory means more security but slower\n• t (iterations) - number of algorithm passes\n• p (threads) - parallelism of calculations\n\nRun the benchmark to find optimal parameters for your computer!",
        "argon2_benchmark_btn": "🚀 Run Argon2ID benchmark",
        "argon2_benchmark_desc": "Benchmark will automatically adjust Argon2ID parameters\nso that the operation takes about 2 seconds on your computer.",
        "argon2_current_params": "📊 Current Argon2ID parameters",
        "argon2_memory": "💾 Memory (m):",
        "argon2_iterations": "🔄 Iterations (t):",
        "argon2_threads": "🧵 Threads (p):",
        "argon2_recommendations": "💡 Recommendations",
        "argon2_tips": "• For laptops: use benchmark results or 'normal' level\n• For desktops: you can use 'high' level\n• Parameter changes only affect NEW files\n• Run benchmark again after hardware changes",
        
        # Appearance tab
        "appearance_group": "🎨 Appearance settings",
        "appearance_dark_mode": "🌙 Dark mode",
        "appearance_notifications": "🔔 Enable notifications",
        
        # Backup tab
        "backup_info_title": "💾 Session backup",
        "backup_info_text": "SafePad automatically saves your session when closing the program.\nThis way you won't lose data even during unexpected shutdown.\n\nBackup is encrypted with a password. You can use the default password or\nset your own for better security.",
        "backup_password_group": "🔑 Backup password",
        "backup_status_custom": "✅ Status: Using custom backup password",
        "backup_status_default": "ℹ️ Status: Using default backup password\n   (recommended to set your own password)",
        "backup_status_error": "⚠️ Status: Cannot check password status",
        "backup_new_password": "New password:",
        "backup_confirm_password": "Confirm password:",
        "backup_save_btn": "💾 Save password",
        "backup_reset_btn": "🔄 Reset to default",
        "backup_tips_title": "💡 Security tips",
        "backup_tips": "• Use a strong, unique password for backups\n• Don't use the same password as for files\n• Remember your password - there is no recovery option\n• Default password is secure but less private\n• Backup is saved in system temporary folder",
        
        # Language tab
        "language_group": "🌐 Language settings",
        "language_select": "Select language:",
        "language_restart_hint": "Language change requires application restart.",
        "language_restart_question": "Language changed. Do you want to restart the application now?",
        
        # Backup password dialogs
        "backup_warning_empty": "Warning",
        "backup_warning_empty_text": "Enter a new password!",
        "backup_error_mismatch": "Error",
        "backup_error_mismatch_text": "Passwords do not match!\n\nEnter the same password in both fields.",
        "backup_warning_weak": "Weak password",
        "backup_warning_weak_text": "Password is less than 6 characters. It may be weak.\n\nAre you sure you want to use this password?",
        "backup_success": "Success",
        "backup_success_save": "✅ Backup password saved!\n\nNew password will be used for next session backup.\nRemember to save it - there is no recovery option!",
        "backup_success_reset": "✅ Default backup password restored!\n\nBackups will now be encrypted with the default password.",
        "backup_reset_confirm_title": "Reset to default password",
        "backup_reset_confirm_text": "Are you sure you want to reset the backup password to default?\n\nYour custom password will be removed.",
        
        # Benchmark
        "benchmark_title": "Argon2ID Benchmark",
        "benchmark_complete": "Benchmark complete",
        "benchmark_complete_text": "✨ Optimal parameters have been selected!\n\nBenchmark results:\n\n💾 Memory: {} MB\n🔄 Iterations: {}\n🧵 Threads: {}\n\nRecommended security levels:\n• 🟢 LOW:   {} MB, {} iterations, {} threads\n• 🟡 MEDIUM: {} MB, {} iterations, {} threads\n• 🔴 HIGH:  {} MB, {} iterations, {} threads\n\n✅ Parameters saved to registry.",
        "benchmark_error": "Benchmark error",
        "benchmark_missing_lib": "argon2-cffi library is not installed.\n\nInstall it with:\npip install argon2-cffi\n\nError: {}",
        "benchmark_start_error": "Failed to start benchmark:\n{}",
        
        # About dialog
        "about_title": "About",
        "about_text": "SafePad {}\n\nSecure text editor with AES-GCM encryption and Argon2ID.\n\nAuthor: {}\n\nFeatures:\n- File encryption\n- Folder encryption\n- Argon2ID with AES-GCM 256\n- Automatic session backup\n- Multi-language support\n- License: MIT",
        
        # File label
        "file_label_none": "No open file",
        "file_label": "File: {}",
        
        # Placeholder
        "placeholder_text": "Welcome to SafePad!\n\nUse File -> New (Ctrl+N) to start writing,\nor File -> Open (Ctrl+O) to open an existing file.",
        
        # Errors
        "error_unknown": "An unknown error occurred",
        
        # Buttons
        "btn_ok": "OK",
        "btn_cancel": "Cancel",
        "btn_yes": "Yes",
        "btn_no": "No",
    }
}


class LanguageManager:
    """Manager for handling application language"""
    
    _instance = None
    _current_language = "pl"
    _translations = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._load_saved_language()
    
    def _load_saved_language(self):
        """Load saved language from registry or file"""
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                r"Software\SafePad", 0, winreg.KEY_READ)
            try:
                lang, _ = winreg.QueryValueEx(key, "language")
                if lang in LANGUAGES:
                    self._current_language = lang
            except:
                pass
            winreg.CloseKey(key)
        except:
            # Fallback to file
            try:
                config_path = os.path.join(os.path.expanduser("~"), ".safepad_config.json")
                if os.path.exists(config_path):
                    with open(config_path, 'r', encoding='utf-8') as f:
                        config = json.load(f)
                        if config.get("language") in LANGUAGES:
                            self._current_language = config["language"]
            except:
                pass
        
        self._translations = TRANSLATIONS.get(self._current_language, TRANSLATIONS["en"])
    
    def save_language(self, language):
        """Save language setting"""
        if language not in LANGUAGES:
            language = "en"
        
        self._current_language = language
        self._translations = TRANSLATIONS.get(language, TRANSLATIONS["en"])
        
        # Save to registry
        try:
            import winreg
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\SafePad")
            winreg.SetValueEx(key, "language", 0, winreg.REG_SZ, language)
            winreg.CloseKey(key)
        except:
            # Fallback to file
            try:
                config_path = os.path.join(os.path.expanduser("~"), ".safepad_config.json")
                config = {}
                if os.path.exists(config_path):
                    with open(config_path, 'r', encoding='utf-8') as f:
                        config = json.load(f)
                config["language"] = language
                with open(config_path, 'w', encoding='utf-8') as f:
                    json.dump(config, f, indent=2)
            except:
                pass
    
    def get_language(self):
        """Get current language code"""
        return self._current_language
    
    def get_language_name(self):
        """Get current language name"""
        return LANGUAGES.get(self._current_language, "English")
    
    def get_available_languages(self):
        """Get list of available languages"""
        return LANGUAGES
    
    def tr(self, key):
        """Get translation for key"""
        if self._translations and key in self._translations:
            return self._translations[key]
        # Fallback to English
        if key in TRANSLATIONS["en"]:
            return TRANSLATIONS["en"][key]
        return key
    
    def format_tr(self, key, *args, **kwargs):
        """Get formatted translation"""
        text = self.tr(key)
        if args:
            return text.format(*args)
        elif kwargs:
            return text.format(**kwargs)
        return text


# Global instance
_lang_manager = None

def get_language_manager():
    """Get the global language manager instance"""
    global _lang_manager
    if _lang_manager is None:
        _lang_manager = LanguageManager()
    return _lang_manager

def tr(key):
    """Shortcut for translation"""
    return get_language_manager().tr(key)

def format_tr(key, *args, **kwargs):
    """Shortcut for formatted translation"""
    return get_language_manager().format_tr(key, *args, **kwargs)