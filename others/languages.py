import json
import os
from pathlib import Path


LANGUAGES = {
    "pl": "Polski",
    "en": "English"
}

# Tłumaczenia (skrócona wersja - dodaj wszystkie potrzebne klucze)
TRANSLATIONS = {
    "pl": {
        "menu_file": "Plik",
        "menu_new": "Nowy",
        "menu_open": "Otwórz...",
        "menu_save": "Zapisz...",
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
        "menu_help": "Pomoc",
        "menu_about": "O programie",
        "menu_show": "Pokaż SafePad",
        "toolbar_new": "Nowy",
        "toolbar_open": "Otwórz",
        "toolbar_save": "Zapisz",
        "toolbar_cut": "Wytnij",
        "toolbar_copy": "Kopiuj",
        "toolbar_paste": "Wklej",
        "status_ready": "Gotowy",
        "status_fullscreen_on": "Tryb pełnoekranowy (naciśnij F11 lub Esc, aby wyjść)",
        "status_fullscreen_off": "Tryb okienkowy",
        "file_label_none": "Brak otwartego pliku",
        "file_label": "Plik: {}",
        "placeholder_text": "Witaj w SafePad!\n\nUżyj Plik -> Nowy (Ctrl+N), aby rozpocząć pisanie,\nlub Plik -> Otwórz (Ctrl+O), aby otworzyć istniejący plik.",
        "settings_title": "Ustawienia SafePad",
        "settings_tab_security": "  🛡️ Bezpieczeństwo  ",
        "settings_tab_argon2": "  ⚙️ Argon2ID  ",
        "settings_tab_appearance": "  🎨 Wygląd  ",
        "settings_tab_backup": "  💾 Backup  ",
        "settings_tab_language": "  🌐 Język  ",
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
        "argon2_info_title": "🔐 Co to jest Argon2ID?",
        "argon2_info_text": "Argon2ID to najnowszy algorytm wyprowadzania klucza...",
        "argon2_benchmark_btn": "🚀 Uruchom benchmark Argon2ID",
        "argon2_benchmark_desc": "Benchmark automatycznie dobierze parametry...",
        "argon2_current_params": "📊 Aktualne parametry Argon2ID",
        "argon2_memory": "💾 Pamięć (m):",
        "argon2_iterations": "🔄 Iteracje (t):",
        "argon2_threads": "🧵 Wątki (p):",
        "argon2_recommendations": "💡 Rekomendacje",
        "argon2_tips": "• Dla laptopów: użyj wyników benchmarku lub poziomu 'normal'\n• Dla komputerów stacjonarnych: możesz użyć poziomu 'high'",
        "appearance_group": "🎨 Ustawienia wyglądu",
        "appearance_dark_mode": "🌙 Tryb ciemny",
        "appearance_notifications": "🔔 Włącz powiadomienia",
        "backup_info_title": "💾 Backup sesji",
        "backup_info_text": "SafePad automatycznie zapisuje twoją sesję przy zamykaniu programu.",
        "backup_password_group": "🔑 Hasło do backupów",
        "backup_status_custom": "✅ Status: Używasz własnego hasła do backupów",
        "backup_status_default": "ℹ️ Status: Używasz domyślnego hasła do backupów",
        "backup_status_error": "⚠️ Status: Nie można sprawdzić statusu hasła",
        "backup_new_password": "Nowe hasło:",
        "backup_confirm_password": "Potwierdź hasło:",
        "backup_save_btn": "💾 Zapisz hasło",
        "backup_reset_btn": "🔄 Przywróć domyślne",
        "backup_tips_title": "💡 Wskazówki bezpieczeństwa",
        "backup_tips": "• Użyj silnego, unikalnego hasła do backupów",
        "language_group": "🌐 Ustawienia języka",
        "language_select": "Wybierz język:",
        "language_restart_hint": "Zmiana języka wymaga ponownego uruchomienia aplikacji.",
        "language_restart_question": "Zmieniono język. Czy chcesz teraz ponownie uruchomić aplikację?",
        "backup_warning_empty": "Uwaga",
        "backup_warning_empty_text": "Wprowadź nowe hasło!",
        "backup_error_mismatch": "Błąd",
        "backup_error_mismatch_text": "Hasła nie są identyczne!",
        "backup_warning_weak": "Słabe hasło",
        "backup_warning_weak_text": "Hasło ma mniej niż 6 znaków. Może być słabe.",
        "backup_success": "Sukces",
        "backup_success_save": "✅ Hasło do backupów zostało zapisane!",
        "backup_success_reset": "✅ Przywrócono domyślne hasło do backupów!",
        "backup_reset_confirm_title": "Przywróć domyślne hasło",
        "backup_reset_confirm_text": "Czy na pewno chcesz przywrócić domyślne hasło do backupów?",
        "benchmark_title": "Benchmark Argon2ID",
        "benchmark_complete": "Benchmark zakończony",
        "benchmark_complete_text": "✨ Optymalne parametry zostały dobrane!",
        "benchmark_error": "Błąd benchmarku",
        "benchmark_missing_lib": "Biblioteka argon2-cffi nie jest zainstalowana.",
        "benchmark_start_error": "Nie udało się uruchomić benchmarku:\n{}",
        "progress_preparing": "Przygotowywanie...",
        "progress_cancel": "Anuluj",
    },
    "en": {
        "menu_file": "File",
        "menu_new": "New",
        "menu_open": "Open...",
        "menu_save": "Save...",
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
        "menu_help": "Help",
        "menu_about": "About",
        "menu_show": "Show SafePad",
        "toolbar_new": "New",
        "toolbar_open": "Open",
        "toolbar_save": "Save",
        "toolbar_cut": "Cut",
        "toolbar_copy": "Copy",
        "toolbar_paste": "Paste",
        "status_ready": "Ready",
        "status_fullscreen_on": "Fullscreen mode (press F11 or Esc to exit)",
        "status_fullscreen_off": "Window mode",
        "file_label_none": "No open file",
        "file_label": "File: {}",
        "placeholder_text": "Welcome to SafePad!\n\nUse File -> New (Ctrl+N) to start writing,\nor File -> Open (Ctrl+O) to open an existing file.",
        "settings_title": "SafePad Settings",
        "settings_tab_security": "  🛡️ Security  ",
        "settings_tab_argon2": "  ⚙️ Argon2ID  ",
        "settings_tab_appearance": "  🎨 Appearance  ",
        "settings_tab_backup": "  💾 Backup  ",
        "settings_tab_language": "  🌐 Language  ",
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
        "argon2_info_title": "🔐 What is Argon2ID?",
        "argon2_info_text": "Argon2ID is the latest key derivation algorithm...",
        "argon2_benchmark_btn": "🚀 Run Argon2ID benchmark",
        "argon2_benchmark_desc": "Benchmark will automatically adjust Argon2ID parameters...",
        "argon2_current_params": "📊 Current Argon2ID parameters",
        "argon2_memory": "💾 Memory (m):",
        "argon2_iterations": "🔄 Iterations (t):",
        "argon2_threads": "🧵 Threads (p):",
        "argon2_recommendations": "💡 Recommendations",
        "argon2_tips": "• For laptops: use benchmark results or 'normal' level\n• For desktops: you can use 'high' level",
        "appearance_group": "🎨 Appearance settings",
        "appearance_dark_mode": "🌙 Dark mode",
        "appearance_notifications": "🔔 Enable notifications",
        "backup_info_title": "💾 Session backup",
        "backup_info_text": "SafePad automatically saves your session when closing the program.",
        "backup_password_group": "🔑 Backup password",
        "backup_status_custom": "✅ Status: Using custom backup password",
        "backup_status_default": "ℹ️ Status: Using default backup password",
        "backup_status_error": "⚠️ Status: Cannot check password status",
        "backup_new_password": "New password:",
        "backup_confirm_password": "Confirm password:",
        "backup_save_btn": "💾 Save password",
        "backup_reset_btn": "🔄 Reset to default",
        "backup_tips_title": "💡 Security tips",
        "backup_tips": "• Use a strong, unique password for backups",
        "language_group": "🌐 Language settings",
        "language_select": "Select language:",
        "language_restart_hint": "Language change requires application restart.",
        "language_restart_question": "Language changed. Do you want to restart the application now?",
        "backup_warning_empty": "Warning",
        "backup_warning_empty_text": "Enter a new password!",
        "backup_error_mismatch": "Error",
        "backup_error_mismatch_text": "Passwords do not match!",
        "backup_warning_weak": "Weak password",
        "backup_warning_weak_text": "Password is less than 6 characters. It may be weak.",
        "backup_success": "Success",
        "backup_success_save": "✅ Backup password saved!",
        "backup_success_reset": "✅ Default backup password restored!",
        "backup_reset_confirm_title": "Reset to default password",
        "backup_reset_confirm_text": "Are you sure you want to reset the backup password to default?",
        "benchmark_title": "Argon2ID Benchmark",
        "benchmark_complete": "Benchmark complete",
        "benchmark_complete_text": "✨ Optimal parameters have been selected!",
        "benchmark_error": "Benchmark error",
        "benchmark_missing_lib": "argon2-cffi library is not installed.",
        "benchmark_start_error": "Failed to start benchmark:\n{}",
        "progress_preparing": "Preparing...",
        "progress_cancel": "Cancel",
    }
}


class LanguageManager:
    """Manager for handling application language"""
    
    _instance = None
    _current_language = "en"
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
        self._config_dir = os.path.join(os.path.expanduser("~"), ".config", "safepad")
        self._config_file = os.path.join(self._config_dir, "config.json")
        self._load_saved_language()
    
    def _load_saved_language(self):
        """Load saved language from config file"""
        try:
            if os.path.exists(self._config_file):
                with open(self._config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    lang = config.get("language", "en")
                    if lang in LANGUAGES:
                        self._current_language = lang
        except:
            pass
        
        self._translations = TRANSLATIONS.get(self._current_language, TRANSLATIONS["en"])
    
    def save_language(self, language):
        """Save language setting"""
        if language not in LANGUAGES:
            language = "en"
        
        self._current_language = language
        self._translations = TRANSLATIONS.get(language, TRANSLATIONS["en"])
        
        try:
            os.makedirs(self._config_dir, exist_ok=True)
            config = {}
            if os.path.exists(self._config_file):
                with open(self._config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            config["language"] = language
            with open(self._config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
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