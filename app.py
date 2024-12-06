from flask import Flask, render_template, request, redirect
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# Инициализация Flask-приложения
app = Flask(__name__)
app.secret_key = "123"

# подключаем Flask-Login
login_manager = LoginManager()

# куда редиректить, если пользователь не авторизован,
# а он пытается попасть на защищенную страницу
login_manager.login_view = "login"
login_manager.init_app(app)

# Словарь для хранения юзеров
users_db = {}

# Модель User с использованием UserMixin
class User(UserMixin):
    def __init__(self, id, name, email, password):
        self.id = id
        self.name = name
        self.email = email
        self.password = password

# показываем Flask-Login как и где найти нужного пользователя
@login_manager.user_loader
def load_user(user_id):
    # Метод get вернет объект users с нужным id
    # со всеми атрибутами и методами класса
    return users_db.get(int(user_id))


@app.route('/')
@login_required
def index():
    return render_template('index.html', name=current_user.name)


# Страница входа
@app.route('/login', methods=['GET', 'POST'])
def login():
    errors = []

    if request.method == "GET":
        return render_template("login.html")

    if request.method == "POST":
        # name_form = request.form.get("name")
        email_form = request.form.get("email")
        password_form = request.form.get("password")

        # Ищем пользователя в словаре
        my_user = None
        for user in users_db.values():
            if user.email == email_form:
                my_user = user
                break

        if my_user is not None:
            if check_password_hash(my_user.password, password_form):
                # Аутентификация пользователя
                login_user(my_user, remember=False)
                return redirect("/")

        if not (email_form or password_form):
            errors.append("Пожалуйста заполните поля email и password")
            return render_template("login.html", errors=errors)
        elif my_user is None:
            errors.append("Такого пользователя не существует")
            return render_template("login.html", errors=errors)
        elif not check_password_hash(my_user.password, password_form):
            errors.append("Введите правильный пароль")
            return render_template("login.html", errors=errors)

    return render_template("login.html")

# Страница регистрации
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    errors = []

    if request.method == 'GET':
        return render_template('signup.html')

    if request.method == 'POST':
        name_form = request.form.get('name')
        email_form = request.form.get('email')
        password_form = request.form.get('password')

        # Проверка существования пользователя
        email_exists = False
        for user in users_db.values():
            if user.email == email_form:
                email_exists = True
                break

        if email_exists:
            errors.append("Пользователь с данным email уже существует")
            return render_template('signup.html', errors=errors)
        elif not (email_form or password_form or name_form):
            errors.append("Пожалуйста заполните все поля")
            return render_template("signup.html", errors=errors)
        elif len(password_form) < 5:
            errors.append("Пароль должен содержать не менее 5 символов")
            return render_template("signup.html", errors=errors)

        # Хэшируем пароль
        hashed_password = generate_password_hash(password_form, method='pbkdf2')
        # создаем объект users с нужными полями
        user_id = str(len(users_db) + 1)  # дел уникальный id
        new_user = User(user_id, name_form, email_form, hashed_password)

        # Добавляем нового пользователя в словарь
        users_db[int(user_id)] = new_user

        return redirect('/login')

    return render_template('signup.html')

# Страница выхода
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/')

# Запуск приложения
if __name__ == '__main__':
    app.run(debug=True)
