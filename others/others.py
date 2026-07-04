# Tutaj jest np benchmark argona, i aktualizacje (ale to w przyszłości, bo teraz nie mam czasu)
"""
others.py - Funkcje pomocnicze i benchmark Argon2ID dla SafePad
Autor: Szofer
Licencja: MIT
"""

import os
import time
import tempfile
import shutil
import json
from datetime import datetime
import multiprocessing


def secure_delete(file_path, passes=3, chunk_size=16 * 1024 * 1024):
    """
    Bezpiecznie usuwa plik poprzez nadpisanie go losowymi danymi.
    
    Nadpisywanie odbywa się w kawałkach (chunk_size), a nie jednym
    `os.urandom(file_size)` na cały plik naraz - dzięki temu duże pliki
    (np. wieloGB zaszyfrowane archiwa folderów) nie powodują skoku zużycia
    pamięci RAM proporcjonalnego do rozmiaru pliku.
    
    Args:
        file_path: Ścieżka do pliku do usunięcia
        passes: Liczba przejść nadpisywania
        chunk_size: Rozmiar kawałka nadpisywanego na raz (w bajtach)
    """
    if not os.path.exists(file_path):
        return
    
    try:
        file_size = os.path.getsize(file_path)
        
        with open(file_path, 'r+b') as f:
            for _ in range(passes):
                f.seek(0)
                remaining = file_size
                while remaining > 0:
                    write_size = min(chunk_size, remaining)
                    f.write(os.urandom(write_size))
                    remaining -= write_size
                f.flush()
                os.fsync(f.fileno())
        
        # Usuń plik
        os.remove(file_path)
        
    except Exception as e:
        print(f"Błąd bezpiecznego usuwania {file_path}: {e}")
        # Fallback - zwykłe usunięcie
        try:
            os.remove(file_path)
        except:
            pass


def format_file_size(size_bytes):
    """
    Formatuje rozmiar pliku w czytelny sposób.
    
    Args:
        size_bytes: Rozmiar w bajtach
    
    Returns:
        string: Sformatowany rozmiar (np. "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} PB"


def get_temp_file_path(prefix="safepad"):
    """
    Zwraca ścieżkę do tymczasowego pliku.
    
    Args:
        prefix: Prefiks nazwy pliku
    
    Returns:
        string: Ścieżka do tymczasowego pliku
    """
    temp_dir = tempfile.gettempdir()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(temp_dir, f"{prefix}_{timestamp}.tmp")


def check_password_requirements(password, settings):
    """
    Sprawdza hasło pod kątem wymagań skonfigurowanych w ustawieniach
    aplikacji (długość minimalna, wielkie/małe litery, cyfry, znaki
    specjalne). Wcześniej te ustawienia były zapisywane i pokazywane w
    oknie Ustawień, ale nigdzie faktycznie nie były egzekwowane przy
    tworzeniu nowego hasła - były czysto kosmetyczne.
    
    Args:
        password: Hasło do sprawdzenia
        settings: Słownik ustawień (z Registryconf.load_settings())
    
    Returns:
        tuple(bool, list[str]): (czy_spelnia_wymagania, lista_opisow_bledow)
    """
    errors = []
    
    min_length = settings.get("password_min_length", 8)
    if len(password) < min_length:
        errors.append(f"Hasło musi mieć co najmniej {min_length} znaków")
    
    if settings.get("password_require_upper", True) and not any(c.isupper() for c in password):
        errors.append("Hasło musi zawierać przynajmniej jedną wielką literę")
    
    if settings.get("password_require_lower", True) and not any(c.islower() for c in password):
        errors.append("Hasło musi zawierać przynajmniej jedną małą literę")
    
    if settings.get("password_require_number", True) and not any(c.isdigit() for c in password):
        errors.append("Hasło musi zawierać przynajmniej jedną cyfrę")
    
    if settings.get("password_require_special", False):
        special_chars = set("!@#$%^&*()-_=+[]{}|;:'\",.<>/?`~\\")
        if not any(c in special_chars for c in password):
            errors.append("Hasło musi zawierać przynajmniej jeden znak specjalny")
    
    return (len(errors) == 0, errors)


def ensure_directory_exists(directory_path):
    """
    Tworzy katalog jeśli nie istnieje.
    
    Args:
        directory_path: Ścieżka do katalogu
    """
    if not os.path.exists(directory_path):
        os.makedirs(directory_path, exist_ok=True)




def get_app_data_dir():
    """
    Zwraca ścieżkę do katalogu danych aplikacji zgodną z XDG.
    
    Returns:
        string: Ścieżka do katalogu ~/.local/share/SafePad
    """
    xdg_data_home = os.environ.get('XDG_DATA_HOME', os.path.expanduser('~/.local/share'))
    return os.path.join(xdg_data_home, 'SafePad')


def clear_temp_files(keep_last=5):
    """
    Czyści stare pliki tymczasowe.
    
    Args:
        keep_last: Liczba plików do zachowania
    """
    temp_dir = tempfile.gettempdir()
    
    try:
        files = []
        for f in os.listdir(temp_dir):
            if f.startswith("safepad_") and f.endswith(".tmp"):
                file_path = os.path.join(temp_dir, f)
                files.append((os.path.getmtime(file_path), file_path))
        
        # Sortuj według czasu modyfikacji (od najstarszych)
        files.sort()
        
        # Usuń starsze pliki
        for i, (_, file_path) in enumerate(files[:-keep_last] if len(files) > keep_last else []):
            try:
                os.remove(file_path)
            except:
                pass
                
    except Exception as e:
        print(f"Błąd czyszczenia plików tymczasowych: {e}")


# ------------------------- BENCHMARK ARGON2ID -------------------------

class Argon2Benchmark:
    """
    Benchmark dla Argon2ID - dostosowuje parametry do możliwości komputera.
    """
    
    TARGET_TIME = 3.0
    
    # Maksymalne parametry dla bezpieczeństwa
    MAX_MEMORY_MB = 4096 
    MAX_TIME_COST = 20     # Maksymalnie 20 iteracji
    MAX_PARALLELISM = multiprocessing.cpu_count()  # Maksymalna liczba wątków
    
    @classmethod
    def run_benchmark(cls, progress_callback=None, status_callback=None):
        """
        Uruchamia benchmark Argon2ID i zwraca optymalne parametry.
        
        Args:
            progress_callback: Funkcja callback dla postępu (0-100)
            status_callback: Funkcja callback dla statusu tekstowego
        
        Returns:
            dict: Optymalne parametry {"m": memory, "t": time, "p": parallelism}
        """
        try:
            import argon2
        except ImportError:
            raise ImportError("Biblioteka 'argon2-cffi' nie jest zainstalowana. Uruchom: pip install argon2-cffi")
        
        # Testowe dane
        password = b"benchmark-test-password-2024"
        salt = os.urandom(16)
        
        # Maksymalna liczba wątków = liczba rdzeni CPU
        max_parallelism = cls.MAX_PARALLELISM
        
        if status_callback:
            status_callback(f"Wykryto {max_parallelism} rdzeni CPU")
        
        # ========== Krok 1: Dobór kosztu pamięci (m) ==========
        if status_callback:
            status_callback("Testowanie kosztu pamięci...")
        
        best_memory = 16 * 1024  # Start: 16 MB (minimum)
        
        # Testuj pamięć od 16 MB do 4096 MB (podwajając)
        memory_levels = [16, 32, 64, 128, 256, 512, 768, 1024, 2048, 4096]
        
        for mem_mb in memory_levels:
            if status_callback:
                status_callback(f"Testowanie {mem_mb} MB pamięci...")
            
            mem_kb = mem_mb * 1024
            parallelism = min(2, max_parallelism)  # Na początku używamy 2 wątków
            
            start_time = time.time()
            try:
                argon2.low_level.hash_secret_raw(
                    secret=password,
                    salt=salt,
                    time_cost=1,  # Minimalna liczba iteracji
                    memory_cost=mem_kb,
                    parallelism=parallelism,
                    hash_len=32,
                    type=argon2.low_level.Type.ID
                )
                elapsed = time.time() - start_time
                
                if progress_callback:
                    progress = int((memory_levels.index(mem_mb) + 1) / len(memory_levels) * 30)
                    progress_callback(progress)
                
                # Jeśli czas przekracza cel, używamy poprzedniej wartości
                if elapsed > cls.TARGET_TIME:
                    best_memory = max(16 * 1024, mem_kb // 2)
                    break
                else:
                    best_memory = mem_kb
                    
            except Exception as e:
                print(f"Błąd przy {mem_mb} MB: {e}")
                best_memory = max(16 * 1024, mem_kb // 2)
                break
        
        if status_callback:
            status_callback(f"Optymalna pamięć: {best_memory // 1024} MB")
        
        # ========== Krok 2: Dobór kosztu czasu (t) ==========
        if status_callback:
            status_callback("Testowanie kosztu czasu (iteracji)...")
        
        best_time_cost = 1
        parallelism = min(2, max_parallelism)
        
        # Testuj iteracje od 1 do 20
        for t in range(1, cls.MAX_TIME_COST + 1):
            if status_callback:
                status_callback(f"Testowanie {t} iteracji...")
            
            start_time = time.time()
            try:
                argon2.low_level.hash_secret_raw(
                    secret=password,
                    salt=salt,
                    time_cost=t,
                    memory_cost=best_memory,
                    parallelism=parallelism,
                    hash_len=32,
                    type=argon2.low_level.Type.ID
                )
                elapsed = time.time() - start_time
                
                if progress_callback:
                    progress = 30 + int((t / cls.MAX_TIME_COST) * 40)
                    progress_callback(progress)
                
                # Jeśli czas przekracza cel, używamy poprzedniej wartości
                if elapsed > cls.TARGET_TIME:
                    best_time_cost = max(1, t - 1)
                    break
                else:
                    best_time_cost = t
                    
            except Exception as e:
                print(f"Błąd przy {t} iteracjach: {e}")
                best_time_cost = max(1, t - 1)
                break
        
        if status_callback:
            status_callback(f"Optymalna liczba iteracji: {best_time_cost}")
        
        # ========== Krok 3: Dobór równoległości (p) ==========
        if status_callback:
            status_callback("Testowanie równoległości (wątków)...")
        
        best_parallelism = min(2, max_parallelism)
        
        # Testuj od 1 do max_parallelism
        for p in range(1, max_parallelism + 1):
            if status_callback:
                status_callback(f"Testowanie {p} wątków...")
            
            start_time = time.time()
            try:
                argon2.low_level.hash_secret_raw(
                    secret=password,
                    salt=salt,
                    time_cost=best_time_cost,
                    memory_cost=best_memory,
                    parallelism=p,
                    hash_len=32,
                    type=argon2.low_level.Type.ID
                )
                elapsed = time.time() - start_time
                
                if progress_callback:
                    progress = 70 + int((p / max_parallelism) * 30)
                    progress_callback(progress)
                
                # Szukamy najlepszego czasu
                if elapsed < cls.TARGET_TIME * 0.8 or p == 1:
                    best_parallelism = p
                else:
                    break
                    
            except Exception as e:
                print(f"Błąd przy {p} wątkach: {e}")
                break
        
        if status_callback:
            status_callback(f"Optymalna liczba wątków: {best_parallelism}")
        
        # ========== Wyniki ==========
        results = {
            "m": best_memory,
            "t": best_time_cost,
            "p": best_parallelism
        }
        
        return results
    
    @classmethod
    def get_level_params(cls, benchmark_results):
        """
        Na podstawie benchmarku tworzy parametry dla trzech poziomów bezpieczeństwa.
        
        Args:
            benchmark_results: Wynik z run_benchmark()
        
        Returns:
            dict: Parametry dla poziomów low, medium, high
        """
        mem = benchmark_results["m"]
        t = benchmark_results["t"]
        p = benchmark_results["p"]
        
        # Poziomy bezpieczeństwa
        return {
            "low": {
                "m": max(16 * 4096, mem // 4),      # 1/4 pamięci benchmarku
                "t": max(1, t // 2),                # 1/2 iteracji
                "p": max(1, p // 2)                 # 1/2 wątków
            },
            "medium": {
                "m": mem,                           # Jak w benchmarku
                "t": t,                             # Jak w benchmarku
                "p": p                              # Jak w benchmarku
            },
            "high": {
                "m": min(cls.MAX_MEMORY_MB * 4096, mem * 2),  # 2x pamięci (max 4GB)
                "t": min(cls.MAX_TIME_COST, t * 2),            # 2x iteracji
                "p": min(cls.MAX_PARALLELISM, p * 2)           # 2x wątków
            }
        }
    
    @classmethod
    def save_benchmark_results(cls, registry_conf, results):
        """
        Zapisuje wyniki benchmarku do konfiguracji.
        
        Args:
            registry_conf: Klasa Registryconf (już zmodyfikowana dla Linuxa)
            results: Wyniki benchmarku
        """
        levels = cls.get_level_params(results)
        
        for level, params in levels.items():
            registry_conf.save_argon_conf(level, params)
        
        # Zapisz informację o ostatnim benchmarku
        settings = registry_conf._read_config(registry_conf.CONFIG_FILE)
        settings['last_benchmark_time'] = datetime.now().isoformat()
        settings['last_benchmark_params'] = json.dumps(results)
        registry_conf._write_config(registry_conf.CONFIG_FILE, settings)


# ------------------------- SZYBKIE PARAMETRY DLA SŁABSZYCH KOMPUTERÓW -------------------------

def get_fallback_params():
    """
    Zwraca bezpieczne domyślne parametry dla słabszych komputerów.
    
    Returns:
        dict: Parametry dla poziomów low, medium, high
    """
    cpu_count = multiprocessing.cpu_count()
    
    return {
        "low": {
            "m": 16 * 1024,      # 16 MB
            "t": 1,              # 1 iteracja
            "p": 1               # 1 wątek
        },
        "medium": {
            "m": 64 * 1024,      # 64 MB
            "t": 2,              # 2 iteracje
            "p": min(2, cpu_count)  # 2 wątki lub mniej
        },
        "high": {
            "m": 256 * 1024,     # 256 MB
            "t": 3,              # 3 iteracje
            "p": min(4, cpu_count)  # 4 wątki lub mniej
        }
    }


def get_quick_params():
    """
    Zwraca szybkie parametry dla bardzo słabych komputerów (netbooki, starsze maszyny).
    
    Returns:
        dict: Szybkie parametry
    """
    return {
        "m": 8 * 1024,      # 8 MB
        "t": 1,             # 1 iteracja
        "p": 1              # 1 wątek
    }


def is_benchmark_needed(registry_conf, max_age_days=30):
    """
    Sprawdza czy potrzebny jest nowy benchmark na podstawie pliku konfiguracyjnego.
    
    Args:
        registry_conf: Klasa Registryconf
        max_age_days: Maksymalny wiek benchmarku w dniach
    
    Returns:
        bool: True jeśli potrzebny nowy benchmark
    """
    settings = registry_conf._read_config(registry_conf.CONFIG_FILE)
    last_time_str = settings.get('last_benchmark_time')
    
    if not last_time_str:
        return True
        
    try:
        last_time = datetime.fromisoformat(last_time_str)
        days_old = (datetime.now() - last_time).days
        return days_old > max_age_days
    except (ValueError, Exception):
        return True