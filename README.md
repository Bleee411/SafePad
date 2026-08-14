
# SafePad 🔒

--------------

![License: MIT](https://img.shields.io/badge/MIT-green?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-FFD43B?style=for-the-badge&logo=python&logoColor=blue)
![Platform](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

--------------

**SafePad** to bezpieczny, szyfrowany edytor tekstu napisany w Pythonie przy użyciu biblioteki PyQt6. Aplikacja przechowuje Twoje notatki w zaszyfrowanym formacie, używając nowoczesnych algorytmów kryptograficznych, aby zapewnić ich prywatność.

## Kluczowe Funkcje

* **Silne Szyfrowanie Plików:** Pliki są szyfrowane przy użyciu **AES-256 w trybie GCM** (AEAD), co zapewnia zarówno poufność, jak i integralność danych.
* **Bezpieczne Wyprowadzanie Kluczy:** Hasła użytkowników są przekształcane w klucze szyfrujące przy użyciu **Argon2ID**, nowoczesnego i odpornego na ataki algorytmu (zamiast starszych, jak PBKDF2).
* **Szyfrowanie Folderów:** Możliwość szyfrowania i deszyfrowania całych folderów.
* **Ochrona Brute-Force:** Aplikacja blokuje się na określony czas po zbyt wielu nieudanych próbach logowania.
* **Wsparcie dla Obrazów:** Możliwość wstawiania i bezpiecznego przechowywania obrazów bezpośrednio w notatkach.
* **Automatyczne Aktualizacje:** Wbudowany system aktualizacji oparty na **PyUpdater** informuje o nowych wersjach i automatycznie je instaluje.
* **Niestandardowy Motyw:** Ciemny motyw "Amber Night" zapewniający komfortową pracę.
* **Narzędzie Migracji:** Pozwala na aktualizację plików zaszyfrowanych w starszych wersjach aplikacji.



## Stos Technologiczny

* **Framework GUI:** PyQt6
* **Kryptografia:** `cryptography` (dla AES-GCM), `argon2-cffi`
* **Obsługa Obrazów:** `Pillow` 
* **Kompilacja:** `PyInstaller`

## 🌍 Platformy
- 🪟 Windows — pełne wsparcie  
- 🐧 Linux — Pełne wsparcie na Debianie 13 (Testowane na Debianie 13)  




## Instalacja i Uruchomienie 

### Uruchamianie (Windows)
1.Pobierz SafePad-2.2.2_Windows.exe z:

[Wersja Stabilna V2.2.2](https://github.com/Bleee411/SafePad/releases/tag/V2.2.2)

2.Otwórz SafePad-2.2.2_Windows.exe i gotowe

### Uruchamianie z kodu żródłowego

1.  Sklonuj repozytorium:
    ```bash
    git clone https://github.com/Bleee411/SafePad.git
    cd SafePad
    ```

2.  Zainstaluj zależności:
    ```bash
    pip install -r requirements.txt
    ```
    ```bash
    sudo apt install libnotify-bin
    ```

3.  Uruchom aplikację:
    ```bash
    python main.py
    ```

### Kompilowanie wersji z kodu żródłowego
1.  Sklonuj repozytorium:
    ```bash
    git clone https://github.com/Bleee411/SafePad.git
    cd SafePad
    ```
    
    2.  Zainstaluj zależności:
    ```bash
    pip install -r requirements.txt
    ```
   (Linux)
   ```bash
    sudo apt install libnotify-bin
   ```
3.
```bash
   pyinstaller --onefile --name="nazwa_pliku_exe" icon="ścieżka_do_ikony" --windowed main.py
```
    
## Screenshots

![Ekran główny](https://github.com/Bleee411/SafePad/blob/main/Screenshots/Zrzut%20ekranu%202025-11-10%20124341.png)
![Ustawienia](https://github.com/Bleee411/SafePad/blob/main/Screenshots/Zrzut%20ekranu%202025-11-10%20124355.png)

## Licencja

Ten projekt jest udostępniany na licencji [MIT](https://choosealicense.com/licenses/mit/) - zobacz plik `LICENSE`, aby uzyskać szczegółowe informacje.

## Disclaimer

> **Uwaga:**  
> Ten projekt SafePad (autorstwa szofer) jest niezależnym notatnikiem szyfrującym  
> napisanym w Pythonie na licencji MIT.  
> Nie jest powiązany z żadnym innym projektem o tej samej nazwie.




