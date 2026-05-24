import sys
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QTabWidget, QLabel, QLineEdit, 
                             QPushButton, QMessageBox, QComboBox)
from PyQt6.QtCore import Qt
from fileworks import read_json, json_writter
from without_salt import hash_without_salt, sign_in_without_salt
from with_salt import hash, sign_in
from registration import registration


class AuthApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Система аутентификации")
        self.setFixedSize(450, 400)
        
        self.settings = read_json("settings.json")
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        storage_layout = QHBoxLayout()
        storage_layout.addWidget(QLabel("Тип хранилища:"))
        self.storage_combo = QComboBox()
        self.storage_combo.addItems(["new_storage (bcrypt)", "old_storage (SHA-256)"])
        self.storage_combo.currentIndexChanged.connect(self.on_storage_changed)
        storage_layout.addWidget(self.storage_combo)
        main_layout.addLayout(storage_layout)
        
        self.tabs = QTabWidget()
        self.setup_registration_tab()
        self.setup_login_tab()
        main_layout.addWidget(self.tabs)
        
        self.on_storage_changed()
    
    def get_storage_path(self):
        if self.storage_combo.currentIndex() == 0:
            return self.settings.get("storage_file", "users_bcrypt.json")
        else:
            return self.settings.get("storage_file_without_salt", "users_sha256.json")
    
    def get_storage_mode(self):
        if self.storage_combo.currentIndex() == 0:
            return self.get_storage_path(), True
        else:
            return self.get_storage_path(), False
    
    def on_storage_changed(self):
        storage_file, use_bcrypt = self.get_storage_mode()
    
    def load_current_users(self):
        storage_file, _ = self.get_storage_mode()
        return read_json(storage_file)
    
    def save_current_users(self, data):
        storage_file, _ = self.get_storage_mode()
        json_writter(storage_file, data)
    
    def setup_registration_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(15)
        
        title = QLabel("РЕГИСТРАЦИЯ")
        title.setStyleSheet("font-size: 16px; font-weight: bold;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        layout.addSpacing(10)
        
        self.reg_login = QLineEdit()
        self.reg_login.setPlaceholderText("Логин")
        self.reg_login.setMinimumHeight(30)
        layout.addWidget(self.reg_login)
        
        self.reg_password = QLineEdit()
        self.reg_password.setPlaceholderText("Пароль")
        self.reg_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.reg_password.setMinimumHeight(30)
        layout.addWidget(self.reg_password)
        
        self.reg_confirm = QLineEdit()
        self.reg_confirm.setPlaceholderText("Подтверждение пароля")
        self.reg_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self.reg_confirm.setMinimumHeight(30)
        layout.addWidget(self.reg_confirm)
        
        layout.addSpacing(20)
        
        reg_btn = QPushButton("Зарегистрироваться")
        reg_btn.setMinimumHeight(35)
        reg_btn.clicked.connect(self.handle_registration)
        layout.addWidget(reg_btn)
        
        layout.addStretch()
        self.tabs.addTab(tab, "Регистрация")
    
    def setup_login_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(15)
        
        title = QLabel("ВХОД")
        title.setStyleSheet("font-size: 16px; font-weight: bold;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        layout.addSpacing(10)
        
        self.login_login = QLineEdit()
        self.login_login.setPlaceholderText("Логин")
        self.login_login.setMinimumHeight(30)
        layout.addWidget(self.login_login)
        
        self.login_password = QLineEdit()
        self.login_password.setPlaceholderText("Пароль")
        self.login_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.login_password.setMinimumHeight(30)
        layout.addWidget(self.login_password)
        
        layout.addSpacing(20)
        
        login_btn = QPushButton("Войти")
        login_btn.setMinimumHeight(35)
        login_btn.clicked.connect(self.handle_login)
        layout.addWidget(login_btn)
        
        layout.addStretch()
        self.tabs.addTab(tab, "Вход")
    
    def handle_registration(self):
        login = self.reg_login.text().strip()
        password = self.reg_password.text()
        confirm = self.reg_confirm.text()
        
        if not login or not password:
            QMessageBox.warning(self, "Ошибка", "Логин и пароль не могут быть пустыми")
            return
        
        if password != confirm:
            QMessageBox.warning(self, "Ошибка", "Пароли не совпадают")
            return
        
        users = self.load_current_users()
        _, use_bcrypt = self.get_storage_mode()
        
        if use_bcrypt:
            hashed = hash(password)
        else:
            hashed = hash_without_salt(password)
        
        if registration(login, hashed, users):
            self.save_current_users(users)
            QMessageBox.information(self, "Успех", "Регистрация успешна!")
            self.reg_login.clear()
            self.reg_password.clear()
            self.reg_confirm.clear()
        else:
            QMessageBox.warning(self, "Ошибка", "Пользователь уже существует")
    
    def handle_login(self):
        login = self.login_login.text().strip()
        password = self.login_password.text()
        
        if not login or not password:
            QMessageBox.warning(self, "Ошибка", "Введите логин и пароль")
            return
        
        users = self.load_current_users()
        _, use_bcrypt = self.get_storage_mode()
        
        if use_bcrypt:
            success = sign_in(login, password, users)
        else:
            success = sign_in_without_salt(login, password, users)
        
        if success:
            QMessageBox.information(self, "Успех", f"Добро пожаловать, {login}!")
            self.login_login.clear()
            self.login_password.clear()
        else:
            QMessageBox.warning(self, "Ошибка", "Неверный логин или пароль")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AuthApp()
    window.show()
    sys.exit(app.exec())