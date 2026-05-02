import os
import subprocess
import sys
from datetime import datetime
from typing import Optional, Dict, Any

class LinuxNotifier:
    
    LOW = "low"
    NORMAL = "normal"
    CRITICAL = "critical"
    
    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"
    
    ICONS = {
        INFO: "dialog-information",
        SUCCESS: "dialog-ok",
        WARNING: "dialog-warning",
        ERROR: "dialog-error"
    }
    
    URGENCY_MAP = {
        INFO: LOW,
        SUCCESS: NORMAL,
        WARNING: NORMAL,
        ERROR: CRITICAL
    }
    
    def __init__(self, app_name: str = "SafePad", app_icon: Optional[str] = None):
        """
        Inicjalizuj system powiadomień
        
        Args:
            app_name: Nazwa aplikacji wyświetlana w powiadomieniach
            app_icon: Ścieżka do ikony aplikacji (opcjonalnie)
        """
        self.app_name = app_name
        self.app_icon = app_icon or self._find_default_icon()
        self.is_available = self._check_notify_send()
        
    def _check_notify_send(self) -> bool:
        """Sprawdź czy notify-send jest dostępny w systemie"""
        try:
            result = subprocess.run(
                ["which", "notify-send"],
                capture_output=True,
                text=True,
                check=False
            )
            return result.returncode == 0 and "notify-send" in result.stdout
        except:
            return False
    
    def _find_default_icon(self) -> str:
        """Znajdź domyślną ikonę dla SafePad"""
        possible_paths = [
            "/usr/share/pixmaps/safepad.png",
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "safe.png"),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.png"),
            "dialog-information"  
        ]
        
        for path in possible_paths:
            if path.startswith("/") and os.path.exists(path):
                return path
            elif os.path.exists(path):
                return path
        
        return "dialog-information"
    
    def send_notification(
        self,
        title: str,
        message: str,
        notification_type: str = INFO,
        timeout: int = 5000,
        show_timestamp: bool = True,
        sound: bool = True
    ) -> bool:
        """
        Wyślij powiadomienie
        
        Args:
            title: Tytuł powiadomienia
            message: Treść powiadomienia
            notification_type: Typ powiadomienia (info/success/warning/error)
            timeout: Czas wyświetlania w milisekundach
            show_timestamp: Czy pokazywać znacznik czasu
            sound: Czy odtworzyć dźwięk powiadomienia
            
        Returns:
            bool: True jeśli powiadomienie zostało wysłane
        """
        if not self.is_available:
            print(f"NOTIFY (simulated): {title} - {message}")
            return False
        
        try:
            urgency = self.URGENCY_MAP.get(notification_type, self.NORMAL)
            icon = self.ICONS.get(notification_type, self.ICONS[self.INFO])
            
            if self.app_icon and os.path.exists(self.app_icon):
                icon = self.app_icon
            
            full_message = message
            if show_timestamp:
                timestamp = datetime.now().strftime("%H:%M:%S")
                full_message = f"{message}\n\n[{timestamp}]"
            
            args = [
                "notify-send",
                title,
                full_message,
                "-u", urgency,
                "-t", str(timeout),
                "-a", self.app_name,
                "-i", icon
            ]
            
            if not sound:
                args.append("--hint=int:transient:1")
            
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                check=False
            )
            
            if result.returncode != 0:
                print(f"Błąd notify-send: {result.stderr}")
                return False
            
            return True
            
        except Exception as e:
            print(f"Błąd wysyłania powiadomienia: {e}")
            return False
    
    def send_file_saved(self, filename: str, duration: float = None):
        """Powiadomienie o zapisaniu pliku"""
        if duration:
            msg = f"Plik '{filename}' został zapisany.\nCzas operacji: {duration:.2f}s"
        else:
            msg = f"Plik '{filename}' został zapisany."
        
        return self.send_notification(
            title="SafePad - Zapisano plik",
            message=msg,
            notification_type=self.SUCCESS,
            timeout=3000
        )
    
    def send_file_opened(self, filename: str):
        """Powiadomienie o otwarciu pliku"""
        return self.send_notification(
            title="SafePad - Otworzono plik",
            message=f"Plik '{filename}' został otwarty.",
            notification_type=self.INFO,
            timeout=3000
        )
    
    def send_encryption_complete(self, filename: str, duration: float):
        """Powiadomienie o zakończeniu szyfrowania"""
        return self.send_notification(
            title="SafePad - Szyfrowanie zakończone",
            message=f"Plik '{filename}' został zaszyfrowany.\nCzas: {duration:.2f}s",
            notification_type=self.SUCCESS,
            timeout=4000
        )
    
    def send_decryption_complete(self, filename: str):
        """Powiadomienie o zakończeniu deszyfrowania"""
        return self.send_notification(
            title="SafePad - Odszyfrowanie zakończone",
            message=f"Plik '{filename}' został odszyfrowany.",
            notification_type=self.SUCCESS,
            timeout=4000
        )
    
    def send_folder_encryption_complete(self, foldername: str, file_count: int):
        """Powiadomienie o zakończeniu szyfrowania folderu"""
        return self.send_notification(
            title="SafePad - Folder zaszyfrowany",
            message=f"Folder '{foldername}' został zaszyfrowany.\nLiczba plików: {file_count}",
            notification_type=self.SUCCESS,
            timeout=5000
        )
    
    def send_folder_decryption_complete(self, foldername: str):
        """Powiadomienie o zakończeniu deszyfrowania folderu"""
        return self.send_notification(
            title="SafePad - Folder odszyfrowany",
            message=f"Folder '{foldername}' został odszyfrowany.",
            notification_type=self.SUCCESS,
            timeout=5000
        )
    
    def send_error(self, title: str, message: str):
        """Powiadomienie o błędzie"""
        return self.send_notification(
            title=f"SafePad - Błąd: {title}",
            message=message,
            notification_type=self.ERROR,
            timeout=6000
        )
    
    def send_warning(self, title: str, message: str):
        """Powiadomienie ostrzegawcze"""
        return self.send_notification(
            title=f"SafePad - Ostrzeżenie: {title}",
            message=message,
            notification_type=self.WARNING,
            timeout=5000
        )
    
    def send_update_available(self, version: str):
        """Powiadomienie o dostępnej aktualizacji"""
        return self.send_notification(
            title="SafePad - Dostępna aktualizacja",
            message=f"Dostępna jest nowa wersja {version}.\nKliknij przycisk w pasku statusu aby zaktualizować.",
            notification_type=self.INFO,
            timeout=10000,
            sound=True
        )
    
    def send_backup_reminder(self):
        """Przypomnienie o backupie"""
        return self.send_notification(
            title="SafePad - Przypomnienie o backupie",
            message="Pamiętaj o regularnym tworzeniu kopii zapasowych zaszyfrowanych plików!",
            notification_type=self.WARNING,
            timeout=8000
        )
    
    def send_test_notification(self):
        """Testowe powiadomienie"""
        return self.send_notification(
            title="SafePad - Test powiadomień",
            message="System powiadomień działa poprawnie!",
            notification_type=self.INFO,
            timeout=3000
        )


# Singleton dla łatwego dostępu
_notifier_instance = None

def get_notifier() -> LinuxNotifier:
    """Pobierz globalną instancję notyfikatora"""
    global _notifier_instance
    if _notifier_instance is None:
        _notifier_instance = LinuxNotifier()
    return _notifier_instance


if __name__ == "__main__":
    notifier = LinuxNotifier()