# SafePad 🔒

--------------

![License: MIT](https://img.shields.io/badge/MIT-green?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-FFD43B?style=for-the-badge&logo=python&logoColor=blue)
![Platform](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)
![Release](https://img.shields.io/badge/Bieżące_wydanie-Beta-orange?style=for-the-badge)

--------------

> ⚠️ **Bieżące wydanie jest wersją BETA.**
> SafePad jako projekt jest rozwijany aktywnie i stabilnie, natomiast obecny
> numer wydania to build beta — może zawierać błędy, w tym teoretycznie takie,
> które mogłyby prowadzić do utraty danych (np. przy operacjach na
> zaszyfrowanych folderach). **Zawsze trzymaj kopię zapasową** ważnych plików
> przed ich zaszyfrowaniem lub odszyfrowaniem tym narzędziem. Zgłoszenia
> błędów i feedback są bardzo mile widziane — pomagają uczynić kolejne
> wydania stabilniejszymi.

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

## 🚧 Status projektu

SafePad znajduje się obecnie w fazie **beta**. Oznacza to:

* Podstawowe funkcje (szyfrowanie/deszyfrowanie plików i folderów, edycja notatek) działają i są testowane, ale nie przeszły jeszcze pełnego, długoterminowego audytu w warunkach produkcyjnych.
* Format zapisu plików oraz sposób wyprowadzania kluczy mogą jeszcze ulec zmianom między wydaniami beta (staramy się zachowywać kompatybilność wsteczną, ale nie jest to gwarantowane na tym etapie).
* Błędy są aktywnie zgłaszane i naprawiane — zalecane jest korzystanie z najnowszej dostępnej wersji.
* Stabilne wydanie 1.0 pojawi się po zakończeniu szerszych testów.

Jeśli znajdziesz błąd lub coś nie działa zgodnie z oczekiwaniami, otwórz proszę **Issue** w repozytorium.

## Licencja

Ten projekt jest udostępniany na licencji [MIT](https://choosealicense.com/licenses/mit/) - zobacz plik `LICENSE`, aby uzyskać szczegółowe informacje.

## Disclaimer

> **Uwaga:**  
> Ten projekt SafePad (autorstwa szofer) jest niezależnym notatnikiem szyfrującym  
> napisanym w Pythonie na licencji MIT.  
> Nie jest powiązany z żadnym innym projektem o tej samej nazwie.
>
> To oprogramowanie jest dostarczane w fazie **beta**, "tak jak jest" (as-is),
> bez żadnych gwarancji. Autor nie ponosi odpowiedzialności za utratę danych
> wynikającą z korzystania z tej aplikacji. Używaj na własną odpowiedzialność
> i zawsze zachowuj kopie zapasowe ważnych plików.