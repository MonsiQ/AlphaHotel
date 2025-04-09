import sys
from datetime import datetime, timedelta
import psycopg2
from PyQt5.QtWidgets import (QApplication, QWidget, QLabel, QLineEdit, QPushButton,
                             QVBoxLayout, QHBoxLayout, QMessageBox, QTableWidget,
                             QTableWidgetItem, QComboBox, QSpacerItem, QSizePolicy)
from PyQt5.QtCore import Qt

SQL = {
    'get_user': """
        SELECT id, role, must_change_pass, failed_attempts, last_login, is_blocked, password 
        FROM users WHERE username = %s
    """,
    'update_login': "UPDATE users SET last_login = NOW(), failed_attempts = 0 WHERE username = %s",
    'block_user': "UPDATE users SET is_blocked = TRUE WHERE username = %s",
    'update_password': "UPDATE users SET password = %s, must_change_pass = FALSE WHERE username = %s",
    'insert_user': "INSERT INTO users (username, password, role, must_change_pass) VALUES (%s, %s, %s, TRUE)",
    'get_all_users': "SELECT id, username, role, is_blocked FROM users",
    'update_user': "UPDATE users SET username = %s, role = %s, is_blocked = %s WHERE id = %s",
    'check_user_exists': "SELECT 1 FROM users WHERE username = %s"
}


class Database:
    def __init__(self):
        self.connection = psycopg2.connect(
            host="localhost",
            database="AlphaHotel",
            user="postgres",
            password="0000",
            port="5432"
        )

    def get_connection(self):
        return self.connection

    def close(self):
        self.connection.close()


class BaseWindow(QWidget):
    def __init__(self, title, min_width=600, min_height=400):
        super().__init__()
        self.setWindowTitle(title)
        self.setMinimumSize(min_width, min_height)
        self.layout = QVBoxLayout()
        self.setLayout(self.layout)


class AuthWindow(BaseWindow):
    def __init__(self):
        super().__init__('Гостиница Alpha - Авторизация', 400, 300)
        self.db = Database()
        self.child_windows = []
        self.setup_ui()

    def setup_ui(self):
        self.login_input = QLineEdit(placeholderText='Логин')
        self.password_input = QLineEdit(placeholderText='Пароль', echoMode=QLineEdit.Password)
        login_btn = QPushButton('Войти', clicked=self.check_auth)

        self.layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))
        self.layout.addWidget(QLabel('Авторизация:', alignment=Qt.AlignCenter))
        self.layout.addWidget(self.login_input, alignment=Qt.AlignCenter)
        self.layout.addWidget(self.password_input, alignment=Qt.AlignCenter)
        self.layout.addWidget(login_btn, alignment=Qt.AlignCenter)
        self.layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))

    def check_auth(self):
        login = self.login_input.text()
        password = self.password_input.text()

        if not login or not password:
            QMessageBox.warning(self, 'Ошибка', 'Заполните все поля')
            return

        with self.db.get_connection().cursor() as cursor:
            cursor.execute(SQL['get_user'], (login,))
            result = cursor.fetchone()

            if not result:
                QMessageBox.warning(self, 'Ошибка',
                                    'Вы ввели неверный логин или пароль. Пожалуйста проверьте ещё раз введенные данные')
                return

            user_id, role, must_change_pass, failed_attempts, last_login, is_blocked, stored_password = result

            if is_blocked:
                QMessageBox.warning(self, 'Ошибка', 'Вы заблокированы. Обратитесь к администратору')
                return

            # Проверка на неактивность более месяца
            if last_login and (datetime.now() - last_login) > timedelta(days=30):
                cursor.execute(SQL['block_user'], (login,))
                self.db.get_connection().commit()
                QMessageBox.warning(self, 'Ошибка', 'Вы заблокированы. Обратитесь к администратору')
                return

            if stored_password != password:
                failed_attempts += 1
                if failed_attempts >= 3:
                    cursor.execute(SQL['block_user'], (login,))
                    self.db.get_connection().commit()
                    QMessageBox.warning(self, 'Ошибка', 'Вы заблокированы. Обратитесь к администратору')
                    return

                cursor.execute("UPDATE users SET failed_attempts = %s WHERE id = %s",
                               (failed_attempts, user_id))
                self.db.get_connection().commit()
                QMessageBox.warning(self, 'Ошибка',
                                    'Вы ввели неверный логин или пароль. Пожалуйста проверьте ещё раз введенные данные')
                return

            cursor.execute(SQL['update_login'], (login,))
            self.db.get_connection().commit()

            QMessageBox.information(self, 'Успех', 'Вы успешно авторизовались')

            if must_change_pass:
                self.open_change_pass_window(login)
            elif role == 'admin':
                self.open_admin_window()
            else:
                self.open_user_window()

            self.hide()

    def open_change_pass_window(self, login):
        window = ChangePassWindow(login, self.db)
        self.child_windows.append(window)
        window.show()

    def open_admin_window(self):
        window = AdminWindow(self.db)
        self.child_windows.append(window)
        window.show()

    def open_user_window(self):
        window = UserWindow()
        self.child_windows.append(window)
        window.show()

    def closeEvent(self, event):
        for window in self.child_windows:
            window.close()
        self.db.close()
        event.accept()


class ChangePassWindow(BaseWindow):
    def __init__(self, login, db):
        super().__init__('Смена пароля', 400, 300)
        self.login = login
        self.db = db
        self.setup_ui()

    def setup_ui(self):
        self.current_pass = QLineEdit(placeholderText='Текущий пароль', echoMode=QLineEdit.Password)
        self.new_pass = QLineEdit(placeholderText='Новый пароль', echoMode=QLineEdit.Password)
        self.confirm_pass = QLineEdit(placeholderText='Подтвердите пароль', echoMode=QLineEdit.Password)
        change_btn = QPushButton('Изменить пароль', clicked=self.change_password)

        self.layout.addWidget(QLabel('Смена пароля:', alignment=Qt.AlignCenter))
        self.layout.addWidget(self.current_pass)
        self.layout.addWidget(self.new_pass)
        self.layout.addWidget(self.confirm_pass)
        self.layout.addWidget(change_btn)

    def change_password(self):
        current_pass = self.current_pass.text()
        new_pass = self.new_pass.text()
        confirm_pass = self.confirm_pass.text()

        if not current_pass or not new_pass or not confirm_pass:
            QMessageBox.warning(self, 'Ошибка', 'Заполните все поля')
            return

        if new_pass != confirm_pass:
            QMessageBox.warning(self, 'Ошибка', 'Новый пароль и подтверждение не совпадают')
            return

        with self.db.get_connection().cursor() as cursor:
            cursor.execute(SQL['get_user'], (self.login,))
            result = cursor.fetchone()
            stored_password = result[6]

            if current_pass != stored_password:
                QMessageBox.warning(self, 'Ошибка', 'Текущий пароль введен неверно')
                return

            cursor.execute(SQL['update_password'], (new_pass, self.login))
            self.db.get_connection().commit()

        QMessageBox.information(self, 'Успех', 'Пароль успешно изменен')
        self.close()

        # Открываем соответствующее окно после смены пароля
        if result[1] == 'admin':
            AdminWindow(self.db).show()
        else:
            UserWindow().show()


class AdminWindow(BaseWindow):
    def __init__(self, db):
        super().__init__('Гостиница Alpha - Администратор', 800, 600)
        self.db = db
        self.child_windows = []
        self.setup_ui()

    def setup_ui(self):
        self.users_table = QTableWidget()
        self.users_table.setColumnCount(4)
        self.users_table.setHorizontalHeaderLabels(['ID', 'Логин', 'Роль', 'Статус'])
        self.users_table.horizontalHeader().setStretchLastSection(True)
        self.users_table.setEditTriggers(QTableWidget.AllEditTriggers)
        self.load_users()

        btn_layout = QHBoxLayout()
        add_user_btn = QPushButton('Добавить пользователя', clicked=self.open_add_user)
        save_btn = QPushButton('Сохранить изменения', clicked=self.save_changes)
        logout_btn = QPushButton('Выйти', clicked=self.logout)

        btn_layout.addWidget(add_user_btn)
        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(logout_btn)

        self.layout.addWidget(QLabel('Список пользователей:'))
        self.layout.addWidget(self.users_table)
        self.layout.addLayout(btn_layout)

    def load_users(self):
        with self.db.get_connection().cursor() as cursor:
            cursor.execute(SQL['get_all_users'])
            users = cursor.fetchall()

            self.users_table.setRowCount(len(users))
            for row, user in enumerate(users):
                for col, value in enumerate(user):
                    item = QTableWidgetItem(str(value))
                    if col == 0:  # ID не редактируется
                        item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                    self.users_table.setItem(row, col, item)

    def save_changes(self):
        try:
            with self.db.get_connection().cursor() as cursor:
                for row in range(self.users_table.rowCount()):
                    user_id = self.users_table.item(row, 0).text()
                    username = self.users_table.item(row, 1).text()
                    role = self.users_table.item(row, 2).text()
                    is_blocked = self.users_table.item(row, 3).text().lower() in ('true', '1')

                    if not username or not role:
                        QMessageBox.warning(self, 'Ошибка', 'Все поля должны быть заполнены')
                        return

                    cursor.execute(SQL['update_user'], (username, role, is_blocked, user_id))

            self.db.get_connection().commit()
            QMessageBox.information(self, 'Успех', 'Изменения сохранены')
            self.load_users()

        except Exception as e:
            self.db.get_connection().rollback()
            QMessageBox.critical(self, 'Ошибка', f'Не удалось сохранить изменения: {str(e)}')

    def open_add_user(self):
        window = AddUserWindow(self.db, self)
        self.child_windows.append(window)
        window.show()

    def logout(self):
        self.close()


class AddUserWindow(BaseWindow):
    def __init__(self, db, parent_window):
        super().__init__('Добавить пользователя', 400, 300)
        self.db = db
        self.parent_window = parent_window
        self.setup_ui()

    def setup_ui(self):
        self.login_input = QLineEdit(placeholderText='Логин')
        self.pass_input = QLineEdit(placeholderText='Пароль', echoMode=QLineEdit.Password)
        self.role_combo = QComboBox()
        self.role_combo.addItems(['user', 'admin'])
        add_btn = QPushButton('Добавить', clicked=self.add_user)

        self.layout.addWidget(QLabel('Добавление нового пользователя:', alignment=Qt.AlignCenter))
        self.layout.addWidget(QLabel('Логин:'))
        self.layout.addWidget(self.login_input)
        self.layout.addWidget(QLabel('Пароль:'))
        self.layout.addWidget(self.pass_input)
        self.layout.addWidget(QLabel('Роль:'))
        self.layout.addWidget(self.role_combo)
        self.layout.addWidget(add_btn)

    def add_user(self):
        login = self.login_input.text()
        password = self.pass_input.text()
        role = self.role_combo.currentText()

        if not login or not password:
            QMessageBox.warning(self, 'Ошибка', 'Заполните все поля')
            return

        try:
            with self.db.get_connection().cursor() as cursor:
                # Проверка существования пользователя
                cursor.execute(SQL['check_user_exists'], (login,))
                if cursor.fetchone():
                    QMessageBox.warning(self, 'Ошибка', 'Пользователь с таким логином уже существует')
                    return

                cursor.execute(SQL['insert_user'], (login, password, role))
                self.db.get_connection().commit()

            QMessageBox.information(self, 'Успех', 'Пользователь добавлен')
            self.parent_window.load_users()
            self.close()

        except Exception as e:
            self.db.get_connection().rollback()
            QMessageBox.critical(self, 'Ошибка', f'Не удалось добавить пользователя: {str(e)}')


class UserWindow(BaseWindow):
    def __init__(self):
        super().__init__('Гостиница Alpha - Пользователь', 600, 400)
        self.setup_ui()

    def setup_ui(self):
        logout_btn = QPushButton('Выйти', clicked=self.close)
        self.layout.addWidget(QLabel('Добро пожаловать в систему гостиницы Alpha!', alignment=Qt.AlignCenter))
        self.layout.addWidget(logout_btn, alignment=Qt.AlignCenter)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = AuthWindow()
    window.show()
    sys.exit(app.exec_())