# ui.py - SafePad GUI z obsługą wielojęzyczności (zakładka języka w ustawieniach)
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

from others.languages import tr, format_tr, LanguageManager, LANGUAGES


class SettingsDialog(QDialog):
    """Settings dialog with PyQt6 and multi-language support"""
    
    def __init__(self, parent=None, settings=None):
        super().__init__(parent)
        self.parent = parent
        self.settings = settings or {}
        self.backup_password_changed = False
        self.setup_ui()
        
    def setup_ui(self):
        """Initialize settings dialog UI"""
        self.setWindowTitle(tr("settings_title"))
        self.setFixedSize(750, 700)
        
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
        tab_widget.addTab(security_tab, tr("settings_tab_security"))
        
        # Argon2 tab
        argon2_tab = QWidget()
        self.setup_argon2_tab(argon2_tab)
        tab_widget.addTab(argon2_tab, tr("settings_tab_argon2"))
        
        # Appearance tab
        appearance_tab = QWidget()
        self.setup_appearance_tab(appearance_tab)
        tab_widget.addTab(appearance_tab, tr("settings_tab_appearance"))
        
        # Backup tab
        backup_tab = QWidget()
        self.setup_backup_tab(backup_tab)
        tab_widget.addTab(backup_tab, tr("settings_tab_backup"))
        
        # Language tab
        language_tab = QWidget()
        self.setup_language_tab(language_tab)
        tab_widget.addTab(language_tab, tr("settings_tab_language"))
        
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
        requirements_group = QGroupBox(tr("security_group_password"))
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
        requirements_layout.addRow(tr("security_min_length"), self.min_length_spin)
        
        # Password requirements checkboxes
        self.require_upper_cb = QCheckBox(tr("security_require_upper"))
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
        
        self.require_lower_cb = QCheckBox(tr("security_require_lower"))
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
        
        self.require_number_cb = QCheckBox(tr("security_require_number"))
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
        
        self.require_special_cb = QCheckBox(tr("security_require_special"))
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
        encryption_group = QGroupBox(tr("security_group_encryption"))
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
            (tr("security_level_low"), "low"),
            (tr("security_level_medium"), "normal"), 
            (tr("security_level_high"), "high")
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
            # Store references with proper attribute names
            setattr(self, f"enc_level_{level}_radio", radio)
        
        layout.addWidget(encryption_group)
        layout.addStretch()
    
    def setup_argon2_tab(self, tab):
        """Setup Argon2ID tab with benchmark button"""
        layout = QVBoxLayout(tab)
        layout.setSpacing(15)
        layout.setContentsMargins(15, 15, 15, 15)
        
        # Information about Argon2ID
        info_group = QGroupBox(tr("argon2_info_title"))
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
        
        info_text = QLabel(tr("argon2_info_text"))
        info_text.setWordWrap(True)
        info_text.setStyleSheet("color: #AAAAAA; font-size: 11px; background: transparent;")
        info_layout.addWidget(info_text)
        layout.addWidget(info_group)
        
        # Benchmark button
        self.benchmark_btn = QPushButton(tr("argon2_benchmark_btn"))
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
        bench_info = QLabel(tr("argon2_benchmark_desc"))
        bench_info.setWordWrap(True)
        bench_info.setStyleSheet("color: #888888; font-size: 10px; background: transparent;")
        bench_info.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(bench_info)
        
        # Current parameters
        params_group = QGroupBox(tr("argon2_current_params"))
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
        
        params_layout.addRow(tr("argon2_memory"), self.current_mem_label)
        params_layout.addRow(tr("argon2_iterations"), self.current_time_label)
        params_layout.addRow(tr("argon2_threads"), self.current_parallel_label)
        
        layout.addWidget(params_group)
        
        # Recommendations
        tips_group = QGroupBox(tr("argon2_recommendations"))
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
        
        tips_text = QLabel(tr("argon2_tips"))
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
        appearance_group = QGroupBox(tr("appearance_group"))
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
        
        self.dark_mode_cb = QCheckBox(tr("appearance_dark_mode"))
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
        
        self.notifications_cb = QCheckBox(tr("appearance_notifications"))
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
    
    def setup_language_tab(self, tab):
        """Setup language tab"""
        layout = QVBoxLayout(tab)
        layout.setSpacing(15)
        layout.setContentsMargins(15, 15, 15, 15)
        
        lang_manager = LanguageManager()
        
        # Language group
        lang_group = QGroupBox(tr("language_group"))
        lang_group.setStyleSheet("""
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
        lang_layout = QVBoxLayout(lang_group)
        lang_layout.setSpacing(10)
        lang_layout.setContentsMargins(15, 20, 15, 15)
        
        # Language selector
        selector_layout = QFormLayout()
        selector_layout.setSpacing(10)
        
        self.language_combo = QComboBox()
        current_lang = lang_manager.get_language()
        
        for code, name in LANGUAGES.items():
            self.language_combo.addItem(name, code)
            if code == current_lang:
                self.language_combo.setCurrentIndex(self.language_combo.count() - 1)
        
        self.language_combo.setStyleSheet("""
            QComboBox {
                background-color: #3C3C3C;
                color: #FAFAFA;
                border: 1px solid #555555;
                padding: 5px;
                border-radius: 3px;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox::down-arrow {
                image: none;
                border: none;
            }
            QComboBox QAbstractItemView {
                background-color: #3C3C3C;
                color: #FAFAFA;
                selection-background-color: #FFC107;
                selection-color: #000000;
            }
        """)
        selector_layout.addRow(tr("language_select"), self.language_combo)
        
        lang_layout.addLayout(selector_layout)
        
        # Restart hint
        hint_label = QLabel(tr("language_restart_hint"))
        hint_label.setWordWrap(True)
        hint_label.setStyleSheet("color: #FFC107; font-size: 11px; background: transparent;")
        lang_layout.addWidget(hint_label)
        
        layout.addWidget(lang_group)
        layout.addStretch()
    
    def setup_backup_tab(self, tab):
        """Setup backup settings tab"""
        layout = QVBoxLayout(tab)
        layout.setSpacing(15)
        layout.setContentsMargins(15, 15, 15, 15)
        
        # Information about backup
        info_group = QGroupBox(tr("backup_info_title"))
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
        
        info_text = QLabel(tr("backup_info_text"))
        info_text.setWordWrap(True)
        info_text.setStyleSheet("color: #AAAAAA; font-size: 11px; background: transparent;")
        info_layout.addWidget(info_text)
        layout.addWidget(info_group)
        
        # Backup password section
        password_group = QGroupBox(tr("backup_password_group"))
        password_group.setStyleSheet("""
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
        password_layout = QVBoxLayout(password_group)
        password_layout.setSpacing(10)
        password_layout.setContentsMargins(15, 20, 15, 15)
        
        # Current password status
        self.backup_status_label = QLabel()
        self.update_backup_status_label()
        self.backup_status_label.setWordWrap(True)
        self.backup_status_label.setStyleSheet("""
            QLabel {
                color: #FFC107;
                font-weight: bold;
                font-size: 12px;
                padding: 8px;
                background-color: #3C3C3C;
                border-radius: 5px;
            }
        """)
        password_layout.addWidget(self.backup_status_label)
        
        password_layout.addSpacing(10)
        
        # New password fields
        password_form = QFormLayout()
        password_form.setSpacing(10)
        
        self.new_backup_password = QLineEdit()
        self.new_backup_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_backup_password.setPlaceholderText(tr("backup_new_password").replace(":", ""))
        self.new_backup_password.setStyleSheet("""
            QLineEdit {
                background-color: #3C3C3C;
                color: #FAFAFA;
                border: 1px solid #555555;
                padding: 8px;
                border-radius: 3px;
            }
            QLineEdit:focus {
                border: 1px solid #FFC107;
            }
            QLineEdit::placeholder {
                color: #888888;
            }
        """)
        password_form.addRow(tr("backup_new_password"), self.new_backup_password)
        
        self.confirm_backup_password = QLineEdit()
        self.confirm_backup_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_backup_password.setPlaceholderText(tr("backup_confirm_password").replace(":", ""))
        self.confirm_backup_password.setStyleSheet("""
            QLineEdit {
                background-color: #3C3C3C;
                color: #FAFAFA;
                border: 1px solid #555555;
                padding: 8px;
                border-radius: 3px;
            }
            QLineEdit:focus {
                border: 1px solid #FFC107;
            }
            QLineEdit::placeholder {
                color: #888888;
            }
        """)
        password_form.addRow(tr("backup_confirm_password"), self.confirm_backup_password)
        
        password_layout.addLayout(password_form)
        
        password_layout.addSpacing(10)
        
        # Buttons
        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(10)
        
        self.save_password_btn = QPushButton(tr("backup_save_btn"))
        self.save_password_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.save_password_btn.setFixedHeight(40)
        self.save_password_btn.setStyleSheet("""
            QPushButton {
                background-color: #FFC107;
                color: #000000;
                border: none;
                border-radius: 5px;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #FFB300;
            }
            QPushButton:pressed {
                background-color: #E0A800;
            }
        """)
        self.save_password_btn.clicked.connect(self.save_backup_password)
        buttons_layout.addWidget(self.save_password_btn)
        
        self.reset_password_btn = QPushButton(tr("backup_reset_btn"))
        self.reset_password_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.reset_password_btn.setFixedHeight(40)
        self.reset_password_btn.setStyleSheet("""
            QPushButton {
                background-color: #555555;
                color: #FAFAFA;
                border: none;
                border-radius: 5px;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #777777;
            }
            QPushButton:pressed {
                background-color: #444444;
            }
        """)
        self.reset_password_btn.clicked.connect(self.reset_backup_password)
        buttons_layout.addWidget(self.reset_password_btn)
        
        password_layout.addLayout(buttons_layout)
        
        layout.addWidget(password_group)
        
        # Security tips
        tips_group = QGroupBox(tr("backup_tips_title"))
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
        
        tips_text = QLabel(tr("backup_tips"))
        tips_text.setWordWrap(True)
        tips_text.setStyleSheet("color: #AAAAAA; font-size: 11px; background: transparent;")
        tips_layout.addWidget(tips_text)
        layout.addWidget(tips_group)
        
        layout.addStretch()
    
    def update_backup_status_label(self):
        """Update the backup password status label"""
        try:
            from crypto.encryption_decryption import Registryconf
            stored_password = Registryconf.load_backup_password()
            
            if stored_password:
                self.backup_status_label.setText(tr("backup_status_custom"))
            else:
                self.backup_status_label.setText(tr("backup_status_default"))
        except:
            self.backup_status_label.setText(tr("backup_status_error"))
    
    def save_backup_password(self):
        """Save new backup password"""
        new_password = self.new_backup_password.text()
        confirm_password = self.confirm_backup_password.text()
        
        if not new_password:
            QMessageBox.warning(self, tr("backup_warning_empty"), tr("backup_warning_empty_text"))
            return
        
        if new_password != confirm_password:
            QMessageBox.critical(self, tr("backup_error_mismatch"), tr("backup_error_mismatch_text"))
            self.confirm_backup_password.clear()
            self.confirm_backup_password.setFocus()
            return
        
        if len(new_password) < 6:
            reply = QMessageBox.question(
                self,
                tr("backup_warning_weak"),
                tr("backup_warning_weak_text"),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.No:
                return
        
        try:
            from crypto.encryption_decryption import Registryconf
            Registryconf.save_backup_password(new_password)
            
            self.new_backup_password.clear()
            self.confirm_backup_password.clear()
            
            self.update_backup_status_label()
            
            # Informuj, że hasło zostało zmienione
            self.backup_password_changed = True
            
            QMessageBox.information(self, tr("backup_success"), tr("backup_success_save"))
            
        except Exception as e:
            QMessageBox.critical(self, tr("backup_error_mismatch"), f"{tr('backup_error_mismatch_text')}\n\n{str(e)}")
    
    def reset_backup_password(self):
        """Reset backup password to default"""
        reply = QMessageBox.question(
            self,
            tr("backup_reset_confirm_title"),
            tr("backup_reset_confirm_text"),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.No:
            return
        
        try:
            from crypto.encryption_decryption import Registryconf
            Registryconf.delete_backup_password()
            
            self.new_backup_password.clear()
            self.confirm_backup_password.clear()
            
            self.update_backup_status_label()
            
            # Informuj, że hasło zostało zmienione
            self.backup_password_changed = True
            
            QMessageBox.information(self, tr("backup_success"), tr("backup_success_reset"))
            
        except Exception as e:
            QMessageBox.critical(self, tr("backup_error_mismatch"), f"{tr('backup_error_mismatch_text')}\n\n{str(e)}")
    
    def run_benchmark(self):
        """Run Argon2ID benchmark"""
        try:
            from others.others import Argon2Benchmark
            from crypto.encryption_decryption import Registryconf
            from PyQt6.QtCore import QThread, pyqtSignal
            
            self.benchmark_progress = QProgressDialog(tr("progress_preparing"), tr("progress_cancel"), 0, 100, self)
            self.benchmark_progress.setWindowTitle(tr("benchmark_title"))
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
            QMessageBox.critical(self, tr("benchmark_error"), 
                format_tr("benchmark_missing_lib", str(e)))
        except Exception as e:
            QMessageBox.critical(self, tr("benchmark_error"), format_tr("benchmark_start_error", str(e)))
    
    def on_benchmark_finished(self, results):
        """Handle benchmark finished"""
        from crypto.encryption_decryption import Registryconf
        from others.others import Argon2Benchmark
        
        self.benchmark_progress.close()
        
        Argon2Benchmark.save_benchmark_results(Registryconf, results)
        
        current_level = self.settings.get("encryption_level", "normal")
        current_params = Registryconf.load_argon_conf(current_level)
        
        self.current_mem_label.setText(f"{current_params.get('m', 65536) // 1024} MB")
        self.current_time_label.setText(str(current_params.get('t', 3)))
        self.current_parallel_label.setText(str(current_params.get('p', 2)))
        
        levels = Argon2Benchmark.get_level_params(results)
        
        msg = QMessageBox(self)
        msg.setWindowTitle(tr("benchmark_complete"))
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setText(tr("benchmark_complete"))
        
        results_text = format_tr(
            "benchmark_complete_text",
            results['m'] // 1024,
            results['t'],
            results['p'],
            levels['low']['m'] // 1024,
            levels['low']['t'],
            levels['low']['p'],
            levels['medium']['m'] // 1024,
            levels['medium']['t'],
            levels['medium']['p'],
            levels['high']['m'] // 1024,
            levels['high']['t'],
            levels['high']['p']
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
        QMessageBox.critical(self, tr("benchmark_error"), 
            f"{tr('benchmark_error')}:\n\n{error_msg}")
    
    def get_settings(self):
        """Get updated settings from dialog"""
        encryption_level = "normal"
        if hasattr(self, 'enc_level_low_radio') and self.enc_level_low_radio.isChecked():
            encryption_level = "low"
        elif hasattr(self, 'enc_level_high_radio') and self.enc_level_high_radio.isChecked():
            encryption_level = "high"
        
        # Save language if changed
        lang_manager = LanguageManager()
        new_language = self.language_combo.currentData()
        language_changed = False
        if new_language != lang_manager.get_language():
            lang_manager.save_language(new_language)
            language_changed = True
        
        return {
            "password_min_length": self.min_length_spin.value(),
            "password_require_upper": self.require_upper_cb.isChecked(),
            "password_require_lower": self.require_lower_cb.isChecked(),
            "password_require_number": self.require_number_cb.isChecked(),
            "password_require_special": self.require_special_cb.isChecked(),
            "encryption_level": encryption_level,
            "dark_mode": self.dark_mode_cb.isChecked(),
            "notifications": self.notifications_cb.isChecked(),
            "remind_later": self.settings.get("remind_later", False),
            "backup_password_changed": self.backup_password_changed,
            "language_changed": language_changed
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
    """Główne okno aplikacji SafePad - tylko GUI z obsługą wielojęzyczności"""
    
    def __init__(self):
        super().__init__()
        self.settings = {}
        self.current_file = None
        
        self.setup_ui()
        self.apply_amber_night_theme()
        self.setup_system_tray()
        self.update_language()
        
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
        self.file_label = QLabel("")
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
        self.status_label = QLabel("")
        self.line_col_label = QLabel("Linia: 1, Kolumna: 1")
        
        self.status_bar.addWidget(self.status_label, 1)
        self.status_bar.addPermanentWidget(self.line_col_label)
        self.setStatusBar(self.status_bar)
        
        # Connect signals
        self.text_edit.cursorPositionChanged.connect(self.update_line_col)
        
        # Menu bar
        self.create_menu_bar()
    
    def update_language(self):
        """Update all GUI texts to current language"""
        # Update file label
        if self.current_file:
            self.file_label.setText(tr("file_label").format(os.path.basename(self.current_file)))
        else:
            self.file_label.setText(tr("file_label_none"))
        
        # Update placeholder
        self.text_edit.setPlaceholderText(tr("placeholder_text"))
        
        # Update status bar
        self.status_label.setText(tr("status_ready"))
        
        # Recreate menu bar and toolbar
        self.create_menu_bar()
        self.create_toolbar()
    
    def toggle_fullscreen(self):
        """Przełącza tryb pełnoekranowy"""
        if self.isFullScreen():
            self.showNormal()
            self.update_status(tr("status_fullscreen_off"))
        else:
            self.showFullScreen()
            self.update_status(tr("status_fullscreen_on"))

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
      file_menu = menubar.addMenu(tr("menu_file"))
    
      self.new_action = QAction(tr("menu_new"), self)
      self.new_action.setShortcut("Ctrl+N")
      file_menu.addAction(self.new_action)
    
      self.open_action = QAction(tr("menu_open"), self)
      self.open_action.setShortcut("Ctrl+O")
      file_menu.addAction(self.open_action)
    
      self.save_action = QAction(tr("menu_save"), self)
      self.save_action.setShortcut("Ctrl+S")
      file_menu.addAction(self.save_action)
    
      file_menu.addSeparator()
    
      self.read_only_action = QAction(tr("menu_read_only"), self)
      file_menu.addAction(self.read_only_action)
    
      file_menu.addSeparator()
    
      self.encrypt_folder_action = QAction(tr("menu_encrypt_folder"), self)
      file_menu.addAction(self.encrypt_folder_action)
    
      self.decrypt_folder_action = QAction(tr("menu_decrypt_folder"), self)
      file_menu.addAction(self.decrypt_folder_action)
    
      file_menu.addSeparator()
    
      self.exit_action = QAction(tr("menu_exit"), self)
      self.exit_action.setShortcut("Alt+F4")
      file_menu.addAction(self.exit_action)
    
      # Edit menu
      edit_menu = menubar.addMenu(tr("menu_edit"))
    
      self.undo_action = QAction(tr("menu_undo"), self)
      self.undo_action.setShortcut("Ctrl+Z")
      edit_menu.addAction(self.undo_action)
    
      self.redo_action = QAction(tr("menu_redo"), self)
      self.redo_action.setShortcut("Ctrl+Y")
      edit_menu.addAction(self.redo_action)
    
      edit_menu.addSeparator()
    
      self.cut_action = QAction(tr("menu_cut"), self)
      self.cut_action.setShortcut("Ctrl+X")
      edit_menu.addAction(self.cut_action)
    
      self.copy_action = QAction(tr("menu_copy"), self)
      self.copy_action.setShortcut("Ctrl+C")
      edit_menu.addAction(self.copy_action)
    
      self.paste_action = QAction(tr("menu_paste"), self)
      self.paste_action.setShortcut("Ctrl+V")
      edit_menu.addAction(self.paste_action)
    
      edit_menu.addSeparator()
    
      self.select_all_action = QAction(tr("menu_select_all"), self)
      self.select_all_action.setShortcut("Ctrl+A")
      edit_menu.addAction(self.select_all_action)
    
      # Settings menu
      settings_menu = menubar.addMenu(tr("menu_settings"))
    
      self.settings_panel_action = QAction(tr("menu_settings_panel"), self)
      settings_menu.addAction(self.settings_panel_action)
    
      # Help menu
      help_menu = menubar.addMenu(tr("menu_help"))
    
      self.about_action = QAction(tr("menu_about"), self)
      help_menu.addAction(self.about_action)
    
      
    
    def create_toolbar(self):
        """Create toolbar at the bottom"""
        self.toolbar = QToolBar()
        self.toolbar.setIconSize(QSize(24, 24))
        self.toolbar.setMovable(False)
        
        while self.toolbar.actions():
            self.toolbar.removeAction(self.toolbar.actions()[0])
        
        buttons = [
            (tr("toolbar_new"), "📄"),
            (tr("toolbar_open"), "📂"),
            (tr("toolbar_save"), "💾"),
            ("", ""),
            (tr("toolbar_cut"), "✂️"),
            (tr("toolbar_copy"), "📋"),
            (tr("toolbar_paste"), "📌"),
        ]
        
        self.toolbar_buttons = []
        
        for text, icon in buttons:
            if not text:
                sep = QFrame()
                sep.setFrameShape(QFrame.Shape.VLine)
                sep.setFrameShadow(QFrame.Shadow.Sunken)
                sep.setStyleSheet("background-color: #555555;")
                sep.setMaximumWidth(2)
                self.toolbar.addWidget(sep)
                self.toolbar_buttons.append(None)
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
            self.toolbar_buttons.append(btn)
    
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
        
        show_action = QAction(tr("menu_show"), self)
        tray_menu.addAction(show_action)
        
        tray_menu.addSeparator()
        
        exit_action = QAction(tr("menu_exit"), self)
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
        if self.current_file:
            self.file_label.setText(tr("file_label").format(os.path.basename(self.current_file)))
        else:
            self.file_label.setText(tr("file_label_none"))
    
    def open_settings_window(self, settings):
        """Open settings window"""
        dialog = SettingsDialog(self, settings)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            new_settings = dialog.get_settings()
            self.settings = new_settings
            
            # Update language if changed
            if new_settings.get("language_changed", False):
                self.update_language()
            
            self.create_menu_bar()
            self.create_toolbar()
            
            return new_settings
        return settings
    
    def get_toolbar_button(self, index):
        """Get toolbar button by index"""
        if 0 <= index < len(self.toolbar_buttons):
            return self.toolbar_buttons[index]
        return None
    
    def get_menu_action(self, menu_name, action_name):
        """Get menu action by name"""
        if menu_name == "file":
            return self.file_menu_actions.get(action_name)
        elif menu_name == "settings":
            return self.settings_menu_actions.get(action_name)
        elif menu_name == "help":
            return self.help_menu_actions.get(action_name)
        return None


def main():
    """Main entry point for GUI testing"""
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    window = SafePadGUI()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()