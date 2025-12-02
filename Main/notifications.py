import os
import sys
import time
from typing import Optional, Dict, Any

class Notifier:
    """System powiadomień dla Windows"""
    
    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"
    
    ICONS = {
        INFO: "info",
        SUCCESS: "ok",
        WARNING: "warning",
        ERROR: "error"
    }
    
    def __init__(self, app_name: str = "SafePad", app_icon: Optional[str] = None):
        """
        Inicjalizuj system powiadomień
        
        Args:
            app_name: Nazwa aplikacji
            app_icon: Ścieżka do ikony .ico (opcjonalnie)
        """
        self.app_name = app_name
        self.app_icon = app_icon or self._find_default_icon()
        self.is_available = self._check_win10toast()
        
        if self.is_available:
            from win10toast import ToastNotifier
            self.notifier = ToastNotifier()
        else:
            self.notifier = None
            print("UWAGA: win10toast nie jest dostępny. Użyj: pip install win10toast")
    
    def _check_win10toast(self) -> bool:
        """Sprawdź czy win10toast jest dostępny"""
        try:
            import win10toast
            return True
        except ImportError:
            return False
    
    def _find_default_icon(self) -> Optional[str]:
        """Znajdź domyślną ikonę .ico dla SafePad"""
        possible_paths = [
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "safe.ico"),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.ico"),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "safe.png"),
            "default"  # Ikona systemowa
        ]
        
        for path in possible_paths:
            if path == "default":
                return None
            if os.path.exists(path):
                return path
        
        return None
    
    def send_notification(
        self,
        title: str,
        message: str,
        notification_type: str = INFO,
        duration: int = 5,
        threaded: bool = True,
        sound: bool = True
    ) -> bool:
        """
        Wyślij powiadomienie Windows
        
        Args:
            title: Tytuł powiadomienia
            message: Treść powiadomienia
            notification_type: Typ powiadomienia
            duration: Czas wyświetlania w sekundach
            threaded: Czy uruchomić w osobnym wątku
            sound: Czy odtworzyć dźwięk
            
        Returns:
            bool: True jeśli powiadomienie zostało wysłane
        """
        if not self.is_available or not self.notifier:
            # Fallback do konsoli
            timestamp = time.strftime("%H:%M:%S")
            print(f"TOAST [{timestamp}]: {title} - {message}")
            return False
        
        try:
            # Przygotuj ikonę
            icon_path = None
            if self.app_icon and os.path.exists(self.app_icon):
                icon_path = self.app_icon
            
            # Mapowanie typów na ikony win10toast
            toast_icon = None
            if icon_path and icon_path.lower().endswith('.ico'):
                toast_icon = icon_path
            
            # Dodaj znacznik czasu
            timestamp = time.strftime("%H:%M:%S")
            full_message = f"{message}\n\n[{timestamp}]"
            
            # Wyślij powiadomienie
            if threaded:
                self.notifier.show_toast(
                    title=title,
                    msg=full_message,
                    icon_path=toast_icon,
                    duration=duration,
                    threaded=True
                )
            else:
                self.notifier.show_toast(
                    title=title,
                    msg=full_message,
                    icon_path=toast_icon,
                    duration=duration,
                    threaded=False
                )
            
            return True
            
        except Exception as e:
            print(f"Błąd wysyłania powiadomienia Windows: {e}")
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
            duration=4
        )
    
    def send_file_opened(self, filename: str):
        """Powiadomienie o otwarciu pliku"""
        return self.send_notification(
            title="SafePad - Otworzono plik",
            message=f"Plik '{filename}' został otwarty.",
            notification_type=self.INFO,
            duration=3
        )
    
    def send_encryption_complete(self, filename: str, duration: float):
        """Powiadomienie o zakończeniu szyfrowania"""
        return self.send_notification(
            title="SafePad - Szyfrowanie zakończone",
            message=f"Plik '{filename}' został zaszyfrowany.\nCzas: {duration:.2f}s",
            notification_type=self.SUCCESS,
            duration=5
        )
    
    def send_decryption_complete(self, filename: str):
        """Powiadomienie o zakończeniu deszyfrowania"""
        return self.send_notification(
            title="SafePad - Odszyfrowanie zakończone",
            message=f"Plik '{filename}' został odszyfrowany.",
            notification_type=self.SUCCESS,
            duration=5
        )
    
    def send_folder_encryption_complete(self, foldername: str, file_count: int):
        """Powiadomienie o zakończeniu szyfrowania folderu"""
        return self.send_notification(
            title="SafePad - Folder zaszyfrowany",
            message=f"Folder '{foldername}' został zaszyfrowany.\nLiczba plików: {file_count}",
            notification_type=self.SUCCESS,
            duration=6
        )
    
    def send_folder_decryption_complete(self, foldername: str):
        """Powiadomienie o zakończeniu deszyfrowania folderu"""
        return self.send_notification(
            title="SafePad - Folder odszyfrowany",
            message=f"Folder '{foldername}' został odszyfrowany.",
            notification_type=self.SUCCESS,
            duration=6
        )
    
    def send_error(self, title: str, message: str):
        """Powiadomienie o błędzie"""
        return self.send_notification(
            title=f"SafePad - Błąd: {title}",
            message=message,
            notification_type=self.ERROR,
            duration=6
        )
    
    def send_warning(self, title: str, message: str):
        """Powiadomienie ostrzegawcze"""
        return self.send_notification(
            title=f"SafePad - Ostrzeżenie: {title}",
            message=message,
            notification_type=self.WARNING,
            duration=5
        )
    
    def send_update_available(self, version: str):
        """Powiadomienie o dostępnej aktualizacji"""
        return self.send_notification(
            title="SafePad - Dostępna aktualizacja",
            message=f"Dostępna jest nowa wersja {version}.\nKliknij przycisk w pasku statusu aby zaktualizować.",
            notification_type=self.INFO,
            duration=10,
            sound=True
        )
    
    def send_backup_reminder(self):
        """Przypomnienie o backupie"""
        return self.send_notification(
            title="SafePad - Przypomnienie o backupie",
            message="Pamiętaj o regularnym tworzeniu kopii zapasowych zaszyfrowanych plików!",
            notification_type=self.WARNING,
            duration=8
        )
    
    def send_test_notification(self):
        """Testowe powiadomienie"""
        return self.send_notification(
            title="SafePad - Test powiadomień",
            message="System powiadomień Windows działa poprawnie!",
            notification_type=self.INFO,
            duration=3
        )


# Singleton dla łatwego dostępu
_notifier_instance = None

def get_notifier() -> Notifier:
    """Pobierz globalną instancję notyfikatora"""
    global _notifier_instance
    if _notifier_instance is None:
        _notifier_instance = Notifier()
    return _notifier_instance


if __name__ == "__main__":
    notifier = Notifier()