from flask import redirect, url_for, flash
from flask_login import login_user, logout_user, current_user
from models import User, db


def register_user(username, email, password, confirm_password, first_name, last_name, role='user', **kwargs):
    # Проверка совпадения паролей
    if password != confirm_password:
        flash('Пароли не совпадают', 'error')
        return False

    # Проверка уникальности username и email
    if User.query.filter_by(username=username).first():
        flash('Это имя пользователя уже занято', 'error')
        return False

    if User.query.filter_by(email=email).first():
        flash('Этот email уже используется', 'error')
        return False

    # Создание нового пользователя
    new_user = User(
        username=username,
        email=email,
        role=role,
        first_name=first_name,
        last_name=last_name,
        **kwargs
    )
    new_user.set_password(password)

    db.session.add(new_user)
    db.session.commit()

    login_user(new_user)
    flash('Регистрация прошла успешно!', 'success')
    return True


def login_user_handler(user, remember=False):
    login_user(user, remember=remember)
    flash('Вы успешно вошли в систему', 'success')
    return True


def logout_user_handler():
    logout_user()
    flash('Вы вышли из системы', 'info')