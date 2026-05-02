import sys
import os
import json
import time
import base64
from io import BytesIO
from PyQt6.QtCore import (Qt, QThread, pyqtSignal, QSize, QTimer, pyqtSlot, QUrl, 
                          QByteArray, QBuffer, QIODevice)
from PyQt6.QtGui import (QAction, QIcon, QPalette, QColor, QFont, QTextCursor, 
                         QPixmap, QKeySequence, QImage, QTextImageFormat, QTextDocument,
                         QGuiApplication)
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QTextEdit, QLabel, QToolBar, QStatusBar, QMenuBar, QMenu,
                            QDialog, QTabWidget, QFormLayout, QCheckBox, QSpinBox,
                            QPushButton, QProgressBar, QMessageBox, QFileDialog,
                            QDialogButtonBox, QFrame, QScrollArea, QLineEdit, 
                            QRadioButton, QButtonGroup, QProgressDialog, QInputDialog,
                            QSizePolicy, QGridLayout, QGroupBox, QSystemTrayIcon,
                            QComboBox, QGraphicsDropShadowEffect)




class SettingsDialog(QDialog):
    """Settings dialog with PyQt6"""
    
    def __init__(self, parent=None, settings=None):
        super().__init__(parent)
        self.parent = parent
        self.settings = settings or {}
        self.setup_ui()
        
    def setup_ui(self):
        """Initialize settings dialog UI"""
        self.setWindowTitle("Ustawienia SafePad")
        self.setFixedSize(750, 650)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Tab widget
        tab_widget = QTabWidget()
        tab_widget.setTabPosition(QTabWidget.TabPosition.West)
        tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #555555;
                background-color: #3C3C3C;
                border-radius: 5px;
            }
            QTabBar::tab {
                background-color: #2B2B2B;
                color: #FAFAFA;
                padding: 10px 15px;
                margin: 2px;
                border-radius: 5px;
            }
            QTabBar::tab:selected {
                background-color: #FFC107;
                color: #000000;
            }
            QTabBar::tab:hover {
                background-color: #FFC107;
                color: #000000;
            }
        """)
        
        # Security tab
        security_tab = QWidget()
        self.setup_security_tab(security_tab)
        tab_widget.addTab(security_tab, "  🛡️ Bezpieczeństwo  ")
        
        # Argon2 tab
        argon2_tab = QWidget()
        self.setup_argon2_tab(argon2_tab)
        tab_widget.addTab(argon2_tab, "  ⚙️ Argon2ID  ")
        
        # Appearance tab
        appearance_tab = QWidget()
        self.setup_appearance_tab(appearance_tab)
        tab_widget.addTab(appearance_tab, "  🎨 Wygląd  ")
        
        layout.addWidget(tab_widget)
        
        # Buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | 
            QDialogButtonBox.StandardButton.Cancel
        )
        button_box.setStyleSheet("""
            QPushButton {
                background-color: #3C3C3C;
                color: #FAFAFA;
                border: none;
                padding: 8px 20px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #FFC107;
                color: #000000;
            }
        """)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
        self.apply_theme()
    
    def setup_security_tab(self, tab):
        """Setup security tab"""
        layout = QVBoxLayout(tab)
        layout.setSpacing(15)
        layout.setContentsMargins(15, 15, 15, 15)
        
        # Password requirements
        requirements_group = QGroupBox("📝 Wymagania hasła")
        requirements_group.setStyleSheet("""
            QGroupBox {
                color: #FAFAFA;
                background-color: #2B2B2B;
                border: 1px solid #555555;
                margin-top: 12px;
                padding-top: 10px;
                font-weight: bold;
                border-radius: 5px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 5px;
                left: 10px;
                background-color: #2B2B2B;
            }
        """)
        requirements_layout = QFormLayout(requirements_group)
        requirements_layout.setSpacing(10)
        requirements_layout.setContentsMargins(15, 20, 15, 15)
        
        # Min password length
        self.min_length_spin = QSpinBox()
        self.min_length_spin.setRange(4, 32)
        self.min_length_spin.setValue(self.settings.get("password_min_length", 8))
        self.min_length_spin.setStyleSheet("""
            QSpinBox {
                background-color: #3C3C3C;
                color: #FAFAFA;
                border: 1px solid #555555;
                padding: 5px;
                border-radius: 3px;
            }
        """)
        requirements_layout.addRow("Minimalna długość hasła:", self.min_length_spin)
        
        # Password requirements checkboxes
        self.require_upper_cb = QCheckBox("Wymagaj wielkich liter (A-Z)")
        self.require_upper_cb.setChecked(self.settings.get("password_require_upper", True))
        self.require_upper_cb.setStyleSheet("""
            QCheckBox {
                color: #FAFAFA;
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
            }
            QCheckBox::indicator:unchecked {
                border: 1px solid #555555;
                background-color: #3C3C3C;
                border-radius: 3px;
            }
            QCheckBox::indicator:checked {
                border: 1px solid #FFC107;
                background-color: #FFC107;
                border-radius: 3px;
            }
        """)
        requirements_layout.addRow(self.require_upper_cb)
        
        self.require_lower_cb = QCheckBox("Wymagaj małych liter (a-z)")
        self.require_lower_cb.setChecked(self.settings.get("password_require_lower", True))
        self.require_lower_cb.setStyleSheet("""
            QCheckBox {
                color: #FAFAFA;
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
            }
            QCheckBox::indicator:unchecked {
                border: 1px solid #555555;
                background-color: #3C3C3C;
                border-radius: 3px;
            }
            QCheckBox::indicator:checked {
                border: 1px solid #FFC107;
                background-color: #FFC107;
                border-radius: 3px;
            }
        """)
        requirements_layout.addRow(self.require_lower_cb)
        
        self.require_number_cb = QCheckBox("Wymagaj cyfr (0-9)")
        self.require_number_cb.setChecked(self.settings.get("password_require_number", True))
        self.require_number_cb.setStyleSheet("""
            QCheckBox {
                color: #FAFAFA;
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
            }
            QCheckBox::indicator:unchecked {
                border: 1px solid #555555;
                background-color: #3C3C3C;
                border-radius: 3px;
            }
            QCheckBox::indicator:checked {
                border: 1px solid #FFC107;
                background-color: #FFC107;
                border-radius: 3px;
            }
        """)
        requirements_layout.addRow(self.require_number_cb)
        
        self.require_special_cb = QCheckBox("Wymagaj znaków specjalnych (!@#...)")
        self.require_special_cb.setChecked(self.settings.get("password_require_special", False))
        self.require_special_cb.setStyleSheet("""
            QCheckBox {
                color: #FAFAFA;
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
            }
            QCheckBox::indicator:unchecked {
                border: 1px solid #555555;
                background-color: #3C3C3C;
                border-radius: 3px;
            }
            QCheckBox::indicator:checked {
                border: 1px solid #FFC107;
                background-color: #FFC107;
                border-radius: 3px;
            }
        """)
        requirements_layout.addRow(self.require_special_cb)
        
        layout.addWidget(requirements_group)
        
        # Encryption level
        encryption_group = QGroupBox("🔒 Poziom szyfrowania")
        encryption_group.setStyleSheet("""
            QGroupBox {
                color: #FAFAFA;
                background-color: #2B2B2B;
                border: 1px solid #555555;
                margin-top: 12px;
                padding-top: 10px;
                font-weight: bold;
                border-radius: 5px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 5px;
                left: 10px;
                background-color: #2B2B2B;
            }
        """)
        encryption_layout = QVBoxLayout(encryption_group)
        encryption_layout.setSpacing(8)
        encryption_layout.setContentsMargins(15, 20, 15, 15)
        
        self.enc_level_group = QButtonGroup(self)
        levels = [
            ("🟢 Niski (szybszy, mniej pamięci)", "low"),
            ("🟡 Normalny (zalecany)", "normal"), 
            ("🔴 Wysoki (najbezpieczniejszy, wolniejszy)", "high")
        ]
        
        current_level = self.settings.get("encryption_level", "normal")
        for text, level in levels:
            radio = QRadioButton(text)
            radio.setChecked(level == current_level)
            radio.setStyleSheet("""
                QRadioButton {
                    color: #FAFAFA;
                    spacing: 8px;
                }
                QRadioButton::indicator {
                    width: 18px;
                    height: 18px;
                }
                QRadioButton::indicator:unchecked {
                    border: 1px solid #555555;
                    background-color: #3C3C3C;
                    border-radius: 9px;
                }
                QRadioButton::indicator:checked {
                    border: 1px solid #FFC107;
                    background-color: #FFC107;
                    border-radius: 9px;
                }
            """)
            self.enc_level_group.addButton(radio)
            encryption_layout.addWidget(radio)
            setattr(self, f"enc_level_{level}_radio", radio)
        
        layout.addWidget(encryption_group)
        layout.addStretch()
    
    def setup_argon2_tab(self, tab):
        """Setup Argon2ID tab with benchmark button"""
        layout = QVBoxLayout(tab)
        layout.setSpacing(15)
        layout.setContentsMargins(15, 15, 15, 15)
        
        # Information about Argon2ID
        info_group = QGroupBox("🔐 Co to jest Argon2ID?")
        info_group.setStyleSheet("""
            QGroupBox {
                color: #FAFAFA;
                background-color: #2B2B2B;
                border: 1px solid #555555;
                margin-top: 12px;
                padding-top: 10px;
                font-weight: bold;
                border-radius: 5px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 5px;
                left: 10px;
                background-color: #2B2B2B;
            }
        """)
        info_layout = QVBoxLayout(info_group)
        info_layout.setContentsMargins(15, 20, 15, 15)
        
        info_text = QLabel(
            "Argon2ID to najnowszy algorytm wyprowadzania klucza, zwycięzca konkursu Password Hashing Competition.\n\n"
            "Optymalne parametry zależą od twojego komputera:\n"
            "• m (pamięć) - im więcej tym bezpieczniej, ale wolniej\n"
            "• t (iteracje) - liczba przejść algorytmu\n"
            "• p (wątki) - równoległość obliczeń\n\n"
            "Uruchom benchmark, aby dobrać optymalne parametry dla swojego komputera!"
        )
        info_text.setWordWrap(True)
        info_text.setStyleSheet("color: #AAAAAA; font-size: 11px; background: transparent;")
        info_layout.addWidget(info_text)
        layout.addWidget(info_group)
        
        # Benchmark button
        self.benchmark_btn = QPushButton("🚀 Uruchom benchmark Argon2ID")
        self.benchmark_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.benchmark_btn.setFixedHeight(50)
        self.benchmark_btn.setStyleSheet("""
            QPushButton {
                background-color: #FFC107;
                color: #000000;
                border: none;
                border-radius: 8px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #FFB300;
            }
            QPushButton:pressed {
                background-color: #E0A800;
            }
        """)
        self.benchmark_btn.clicked.connect(self.run_benchmark)
        layout.addWidget(self.benchmark_btn)
        
        # Benchmark description
        bench_info = QLabel(
            "Benchmark automatycznie dobierze parametry Argon2ID tak,\n"
            "aby operacja trwała około 2 sekundy na twoim komputerze.\n\n"
        )
        bench_info.setWordWrap(True)
        bench_info.setStyleSheet("color: #888888; font-size: 10px; background: transparent;")
        bench_info.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(bench_info)
        
        # Current parameters
        params_group = QGroupBox("📊 Aktualne parametry Argon2ID")
        params_group.setStyleSheet("""
            QGroupBox {
                color: #FAFAFA;
                background-color: #2B2B2B;
                border: 1px solid #555555;
                margin-top: 12px;
                padding-top: 10px;
                font-weight: bold;
                border-radius: 5px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 5px;
                left: 10px;
                background-color: #2B2B2B;
            }
        """)
        params_layout = QFormLayout(params_group)
        params_layout.setSpacing(10)
        params_layout.setContentsMargins(15, 20, 15, 15)
        
        # Load current parameters from registry
        try:
            from crypto.encryption_decryption import Registryconf
            current_level = self.settings.get("encryption_level", "normal")
            current_params = Registryconf.load_argon_conf(current_level)
            
            self.current_mem_label = QLabel(f"{current_params.get('m', 65536) // 1024} MB")
            self.current_time_label = QLabel(str(current_params.get('t', 3)))
            self.current_parallel_label = QLabel(str(current_params.get('p', 2)))
        except:
            self.current_mem_label = QLabel("64 MB")
            self.current_time_label = QLabel("3")
            self.current_parallel_label = QLabel("2")
        
        self.current_mem_label.setStyleSheet("color: #FFC107; font-weight: bold;")
        self.current_time_label.setStyleSheet("color: #FFC107; font-weight: bold;")
        self.current_parallel_label.setStyleSheet("color: #FFC107; font-weight: bold;")
        
        params_layout.addRow("💾 Pamięć (m):", self.current_mem_label)
        params_layout.addRow("🔄 Iteracje (t):", self.current_time_label)
        params_layout.addRow("🧵 Wątki (p):", self.current_parallel_label)
        
        layout.addWidget(params_group)
        
        # Recommendations
        tips_group = QGroupBox("💡 Rekomendacje")
        tips_group.setStyleSheet("""
            QGroupBox {
                color: #FAFAFA;
                background-color: #2B2B2B;
                border: 1px solid #555555;
                margin-top: 12px;
                padding-top: 10px;
                font-weight: bold;
                border-radius: 5px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 5px;
                left: 10px;
                background-color: #2B2B2B;
            }
        """)
        tips_layout = QVBoxLayout(tips_group)
        tips_layout.setContentsMargins(15, 20, 15, 15)
        
        tips_text = QLabel(
            "• Dla laptopów: użyj wyników benchmarku lub poziomu 'normal'\n"
            "• Dla komputerów stacjonarnych: możesz użyć poziomu 'high'\n"
            "• Zmiana parametrów wpływa tylko na NOWE pliki\n"
            "• Benchmark uruchom ponownie po zmianie sprzętu"
        )
        tips_text.setWordWrap(True)
        tips_text.setStyleSheet("color: #AAAAAA; font-size: 11px; background: transparent;")
        tips_layout.addWidget(tips_text)
        layout.addWidget(tips_group)
        
        layout.addStretch()
    
    def setup_appearance_tab(self, tab):
        """Setup appearance tab"""
        layout = QVBoxLayout(tab)
        layout.setSpacing(15)
        layout.setContentsMargins(15, 15, 15, 15)
        
        # Appearance settings
        appearance_group = QGroupBox("🎨 Ustawienia wyglądu")
        appearance_group.setStyleSheet("""
            QGroupBox {
                color: #FAFAFA;
                background-color: #2B2B2B;
                border: 1px solid #555555;
                margin-top: 12px;
                padding-top: 10px;
                font-weight: bold;
                border-radius: 5px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 5px;
                left: 10px;
                background-color: #2B2B2B;
            }
        """)
        appearance_layout = QVBoxLayout(appearance_group)
        appearance_layout.setSpacing(10)
        appearance_layout.setContentsMargins(15, 20, 15, 15)
        
        self.dark_mode_cb = QCheckBox("🌙 Tryb ciemny")
        self.dark_mode_cb.setChecked(self.settings.get("dark_mode", True))
        self.dark_mode_cb.setStyleSheet("""
            QCheckBox {
                color: #FAFAFA;
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
            }
            QCheckBox::indicator:unchecked {
                border: 1px solid #555555;
                background-color: #3C3C3C;
                border-radius: 3px;
            }
            QCheckBox::indicator:checked {
                border: 1px solid #FFC107;
                background-color: #FFC107;
                border-radius: 3px;
            }
        """)
        appearance_layout.addWidget(self.dark_mode_cb)
        
        self.notifications_cb = QCheckBox("🔔 Włącz powiadomienia")
        self.notifications_cb.setChecked(self.settings.get("notifications", True))
        self.notifications_cb.setStyleSheet("""
            QCheckBox {
                color: #FAFAFA;
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
            }
            QCheckBox::indicator:unchecked {
                border: 1px solid #555555;
                background-color: #3C3C3C;
                border-radius: 3px;
            }
            QCheckBox::indicator:checked {
                border: 1px solid #FFC107;
                background-color: #FFC107;
                border-radius: 3px;
            }
        """)
        appearance_layout.addWidget(self.notifications_cb)
        
        layout.addWidget(appearance_group)
        layout.addStretch()
    
    def run_benchmark(self):
        """Run Argon2ID benchmark"""
        try:
            from others.others import Argon2Benchmark
            from crypto.encryption_decryption import Registryconf
            from PyQt6.QtCore import QThread, pyqtSignal
            
            # Progress dialog
            self.benchmark_progress = QProgressDialog("Przygotowywanie benchmarku...", "Anuluj", 0, 100, self)
            self.benchmark_progress.setWindowTitle("Benchmark Argon2ID")
            self.benchmark_progress.setWindowModality(Qt.WindowModality.WindowModal)
            self.benchmark_progress.setAutoClose(True)
            self.benchmark_progress.setMinimumDuration(0)
            self.benchmark_progress.setStyleSheet("""
                QProgressDialog {
                    background-color: #2B2B2B;
                    color: #FAFAFA;
                }
                QLabel {
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
                QPushButton {
                    background-color: #3C3C3C;
                    color: #FAFAFA;
                    border: 1px solid #555555;
                    padding: 5px 15px;
                    border-radius: 3px;
                }
                QPushButton:hover {
                    background-color: #FFC107;
                    color: #000000;
                }
            """)
            
            # Benchmark thread
            class BenchmarkThread(QThread):
                progress = pyqtSignal(int)
                status = pyqtSignal(str)
                finished = pyqtSignal(dict)
                error = pyqtSignal(str)
                
                def run(self):
                    try:
                        results = Argon2Benchmark.run_benchmark(
                            progress_callback=lambda p: self.progress.emit(p),
                            status_callback=lambda s: self.status.emit(s)
                        )
                        self.finished.emit(results)
                    except Exception as e:
                        self.error.emit(str(e))
            
            self.benchmark_thread = BenchmarkThread()
            self.benchmark_thread.progress.connect(self.benchmark_progress.setValue)
            self.benchmark_thread.status.connect(self.benchmark_progress.setLabelText)
            self.benchmark_thread.finished.connect(self.on_benchmark_finished)
            self.benchmark_thread.error.connect(self.on_benchmark_error)
            self.benchmark_progress.canceled.connect(self.benchmark_thread.terminate)
            
            self.benchmark_thread.start()
            self.benchmark_progress.exec()
            
        except ImportError as e:
            QMessageBox.critical(self, "Błąd", 
                f"Biblioteka argon2-cffi nie jest zainstalowana.\n\nZainstaluj ją komendą:\npip install argon2-cffi\n\nBłąd: {e}")
        except Exception as e:
            QMessageBox.critical(self, "Błąd", f"Nie udało się uruchomić benchmarku:\n{e}")
    
    def on_benchmark_finished(self, results):
        """Handle benchmark finished"""
        from crypto.encryption_decryption import Registryconf
        from others.others import Argon2Benchmark
        
        self.benchmark_progress.close()
        
        # Save results to registry
        Argon2Benchmark.save_benchmark_results(Registryconf, results)
        
        # Update displayed parameters
        current_level = self.settings.get("encryption_level", "normal")
        current_params = Registryconf.load_argon_conf(current_level)
        
        self.current_mem_label.setText(f"{current_params.get('m', 65536) // 1024} MB")
        self.current_time_label.setText(str(current_params.get('t', 3)))
        self.current_parallel_label.setText(str(current_params.get('p', 2)))
        
        # Show results
        levels = Argon2Benchmark.get_level_params(results)
        
        msg = QMessageBox(self)
        msg.setWindowTitle("Benchmark zakończony")
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setText("✨ Optymalne parametry zostały dobrane!")
        
        results_text = (
            f"Wynik benchmarku:\n\n"
            f"💾 Pamięć: {results['m'] // 1024} MB\n"
            f"🔄 Iteracje: {results['t']}\n"
            f"🧵 Wątki: {results['p']}\n\n"
            f"Zalecane poziomy bezpieczeństwa:\n"
            f"• 🟢 LOW:   {levels['low']['m'] // 1024} MB, {levels['low']['t']} iteracji, {levels['low']['p']} wątków\n"
            f"• 🟡 MEDIUM: {levels['medium']['m'] // 1024} MB, {levels['medium']['t']} iteracji, {levels['medium']['p']} wątków\n"
            f"• 🔴 HIGH:  {levels['high']['m'] // 1024} MB, {levels['high']['t']} iteracji, {levels['high']['p']} wątków\n\n"
            f"✅ Parametry zapisano w rejestrze."
        )
        msg.setInformativeText(results_text)
        msg.setStyleSheet("""
            QMessageBox {
                background-color: #2B2B2B;
                color: #FAFAFA;
            }
            QLabel {
                color: #FAFAFA;
            }
            QPushButton {
                background-color: #3C3C3C;
                color: #FAFAFA;
                padding: 8px 20px;
                border: none;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #FFC107;
                color: #000000;
            }
        """)
        msg.exec()
    
    def on_benchmark_error(self, error_msg):
        """Handle benchmark error"""
        self.benchmark_progress.close()
        QMessageBox.critical(self, "Błąd benchmarku", 
            f"Wystąpił błąd podczas benchmarku:\n\n{error_msg}")
    
    def get_settings(self):
        """Get updated settings from dialog"""
        encryption_level = "normal"
        if hasattr(self, 'enc_level_low_radio') and self.enc_level_low_radio.isChecked():
            encryption_level = "low"
        elif hasattr(self, 'enc_level_high_radio') and self.enc_level_high_radio.isChecked():
            encryption_level = "high"
        
        return {
            "password_min_length": self.min_length_spin.value(),
            "password_require_upper": self.require_upper_cb.isChecked(),
            "password_require_lower": self.require_lower_cb.isChecked(),
            "password_require_number": self.require_number_cb.isChecked(),
            "password_require_special": self.require_special_cb.isChecked(),
            "encryption_level": encryption_level,
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
            }
            QLabel {
                color: #FAFAFA;
            }
            QSpinBox {
                background-color: #3C3C3C;
                color: #FAFAFA;
                border: 1px solid #555555;
                padding: 5px;
                border-radius: 3px;
            }
            QLineEdit {
                background-color: #3C3C3C;
                color: #FAFAFA;
                border: 1px solid #555555;
                padding: 5px;
                border-radius: 3px;
            }
            QComboBox {
                background-color: #3C3C3C;
                color: #FAFAFA;
                border: 1px solid #555555;
                padding: 5px;
                border-radius: 3px;
            }
            QPushButton {
                background-color: #3C3C3C;
                color: #FAFAFA;
                border: none;
                padding: 8px 15px;
                border-radius: 3px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #FFC107;
                color: #000000;
            }
        """)


class SafePadGUI(QMainWindow):
    """Główne okno aplikacji SafePad - tylko GUI"""
    
    def __init__(self):
        super().__init__()
        self.settings = {}
        
        self.setup_ui()
        self.apply_amber_night_theme()
        self.setup_system_tray()
        
    def setup_ui(self):
        """Initialize GUI components"""
        self.setWindowTitle("SafePad")
        self.setGeometry(100, 100, 1200, 800)
        
        # Central widget
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
            }
        """)
        main_layout.addWidget(self.file_label)
        
        # Text edit
        self.text_edit = QTextEdit()
        welcome_text = (
            "Witaj w SafePad!\n\n"
            "Użyj Plik -> Nowy (Ctrl+N), aby rozpocząć pisanie,\n"
            "lub Plik -> Otwórz (Ctrl+O), aby otworzyć istniejący plik.\n\n"
        )
        self.text_edit.setPlaceholderText(welcome_text)
        self.text_edit.setAlignment(Qt.AlignmentFlag.AlignLeft)
        self.text_edit.setStyleSheet("""
            QTextEdit {
                background-color: #3C3C3C;
                color: #FAFAFA;
                border: none;
                font-family: Consolas;
                font-size: 12px;
                selection-background-color: #FFC107;
                selection-color: #000000;
            }
            QTextEdit::placeholder {
                color: #888888;
            }
        """)
        main_layout.addWidget(self.text_edit)
        
        # Toolbar
        self.create_toolbar()
        main_layout.addWidget(self.toolbar)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.status_label = QLabel("Gotowy")
        self.line_col_label = QLabel("Linia: 1, Kolumna: 1")
        
        self.status_bar.addWidget(self.status_label, 1)
        self.status_bar.addPermanentWidget(self.line_col_label)
        self.setStatusBar(self.status_bar)
        
        # Connect signals
        self.text_edit.cursorPositionChanged.connect(self.update_line_col)
        
        # Menu bar
        self.create_menu_bar()
        
    def toggle_fullscreen(self):
      """Przełącza tryb pełnoekranowy"""
      if self.isFullScreen():
        self.showNormal()
        self.update_status("Tryb okienkowy")
      else:
        self.showFullScreen()
        self.update_status("Tryb pełnoekranowy (naciśnij F11 lub Esc, aby wyjść)")

    def keyPressEvent(self, event):
      """Obsługa klawiszy globalnych"""
      if event.key() == Qt.Key.Key_F11:
         self.toggle_fullscreen()
      elif event.key() == Qt.Key.Key_Escape and self.isFullScreen():
        self.toggle_fullscreen()
      else:
        super().keyPressEvent(event)
        
    def create_menu_bar(self):
        """Create menu bar"""
        menubar = self.menuBar()
    
        if menubar.actions():
          menubar.clear()
    
        # File menu
        file_menu = menubar.addMenu("Plik")
    
        new_action = QAction("Nowy", self)
        new_action.setShortcut("Ctrl+N")
        file_menu.addAction(new_action)
    
        open_action = QAction("Otwórz...", self)
        open_action.setShortcut("Ctrl+O")
        file_menu.addAction(open_action)
    
        save_action = QAction("Zapisz...", self)
        save_action.setShortcut("Ctrl+S")
        file_menu.addAction(save_action)
    
        file_menu.addSeparator()
    
        read_only_action = QAction("Tryb tylko do odczytu", self)
        file_menu.addAction(read_only_action)
    
        file_menu.addSeparator()
    
        encrypt_folder_action = QAction("Zaszyfruj folder", self)
        file_menu.addAction(encrypt_folder_action)
    
        decrypt_folder_action = QAction("Odszyfruj folder", self)
        file_menu.addAction(decrypt_folder_action)
    
        file_menu.addSeparator()
    
    
        file_menu.addSeparator()
    
        exit_action = QAction("Zakończ", self)
        exit_action.setShortcut("Alt+F4")
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
        
        # Settings menu
        settings_menu = menubar.addMenu("Ustawienia")
        
        settings_panel_action = QAction("Panel ustawień", self)
        settings_menu.addAction(settings_panel_action)
        
        # Help menu
        help_menu = menubar.addMenu("Pomoc")
        
        about_action = QAction("O programie", self)
        help_menu.addAction(about_action)
        
    def create_toolbar(self):
        """Create toolbar at the bottom"""
        self.toolbar = QToolBar()
        self.toolbar.setIconSize(QSize(24, 24))
        self.toolbar.setMovable(False)
        
        while self.toolbar.actions():
            self.toolbar.removeAction(self.toolbar.actions()[0])
        
        buttons = [
            ("Nowy", "📄"),
            ("Otwórz", "📂"),
            ("Zapisz", "💾"),
            ("", ""),
            ("Wytnij", "✂️"),
            ("Kopiuj", "📋"),
            ("Wklej", "📌"),
        ]
        
        for text, icon in buttons:
            if not text:
                sep = QFrame()
                sep.setFrameShape(QFrame.Shape.VLine)
                sep.setFrameShadow(QFrame.Shadow.Sunken)
                sep.setStyleSheet("background-color: #555555;")
                sep.setMaximumWidth(2)
                self.toolbar.addWidget(sep)
                continue
                
            btn = QPushButton(f"{icon} {text}")
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #3C3C3C;
                    color: #FAFAFA;
                    border: none;
                    padding: 8px 12px;
                    margin: 2px;
                    border-radius: 3px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #FFC107;
                    color: #000000;
                }
                QPushButton:pressed {
                    background-color: #FFB300;
                }
            """)
            self.toolbar.addWidget(btn)
    
    def apply_amber_night_theme(self):
        """Apply Amber Night theme to the application"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2B2B2B;
                color: #FAFAFA;
            }
            QMenuBar {
                background-color: #2B2B2B;
                color: #FAFAFA;
                border-bottom: 1px solid #555555;
            }
            QMenuBar::item {
                background-color: transparent;
                padding: 4px 8px;
            }
            QMenuBar::item:selected {
                background-color: #FFC107;
                color: #000000;
            }
            QMenu {
                background-color: #3C3C3C;
                color: #FAFAFA;
                border: 1px solid #555555;
            }
            QMenu::item {
                padding: 4px 20px;
            }
            QMenu::item:selected {
                background-color: #FFC107;
                color: #000000;
            }
            QStatusBar {
                background-color: #2B2B2B;
                color: #FAFAFA;
                border-top: 1px solid #555555;
            }
            QToolBar {
                background-color: #3C3C3C;
                border: none;
                spacing: 2px;
                padding: 2px;
                border-top: 1px solid #555555;
            }
            QMessageBox {
                background-color: #2B2B2B;
                color: #FAFAFA;
            }
            QMessageBox QLabel {
                color: #FAFAFA;
            }
            QMessageBox QPushButton {
                background-color: #3C3C3C;
                color: #FAFAFA;
                padding: 5px 15px;
                border: none;
                border-radius: 3px;
            }
            QMessageBox QPushButton:hover {
                background-color: #FFC107;
                color: #000000;
            }
        """)
    
    def setup_system_tray(self):
        """Setup system tray icon and menu"""
        self.tray_icon = QSystemTrayIcon(self)
        
        # Create a simple icon
        pixmap = QPixmap(64, 64)
        pixmap.fill(QColor("#FFC107"))
        self.tray_icon.setIcon(QIcon(pixmap))
        
        # Create tray menu
        tray_menu = QMenu()
        
        show_action = QAction("Pokaż SafePad", self)
        tray_menu.addAction(show_action)
        
        
        tray_menu.addSeparator()
        
        exit_action = QAction("Zakończ", self)
        tray_menu.addAction(exit_action)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()
        
    
    def update_line_col(self):
        """Update line and column information in status bar"""
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
    
    
    
    def open_settings_window(self, settings):
        """Open settings window"""
        dialog = SettingsDialog(self, settings)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            new_settings = dialog.get_settings()
            self.settings = new_settings
            
            self.create_menu_bar()
            self.create_toolbar()
            
            return new_settings
        return settings


def main():
    """Main entry point for GUI testing"""
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    window = SafePadGUI()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()