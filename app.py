from flask_sqlalchemy import SQLAlchemy
from flask import Flask, render_template, request, redirect, url_for,session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
import os
import uuid
from datetime import datetime
from werkzeug.utils import secure_filename
from sqlalchemy import inspect, text

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///site.db"

db = SQLAlchemy(app)

app.config["SECRET_KEY"] = "9e1e4dd7bbac25f6acff1b97a6c78961252fcc4224ed557130b84d7f40bf0ff4" # ЗАХИСТ1

csrf = CSRFProtect(app) # ЗАХИСТ13: перевіряємо CSRF-токени для захисту POST-запитів

app.config["UPLOAD_FOLDER"] = os.path.join(
    app.root_path, "static", "uploads"
)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024 # ЗАХИСТ15: обмежуємо розмір запиту до 5 МБ

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

@app.route('/')
def index():
    return render_template("home.html")

@app.route('/base')
def base():
    return render_template("base.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        if not name or not email or not password:
            return render_template(
                "register.html",
                error="Заповни всі поля."
            )

        if len(password) < 8: # ЗАХИСТ2: вимагаємо пароль мінімум із 8 символів
            return render_template(
                "register.html",
                error="Пароль має містити щонайменше 8 символів."
            )

        existing_user = User.query.filter_by(email=email).first()

        if existing_user: # ЗАХИСТ4: не дозволяємо повторну реєстрацію з тим самим email
            return render_template(
                "register.html",
                error="Користувач із таким email уже існує."
            )

        hashed_password = generate_password_hash(password) # ЗАХИСТ3: зберігаємо хеш пароля замість самого пароля

        new_user = User(
            name=name,
            email=email,
            password=hashed_password
        )

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template("register.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password): # ЗАХИСТ5: перевіряємо пароль за його хешем
            session.clear() # ЗАХИСТ6: очищаємо стару сесію перед входом
            session['user_id'] = user.id
            return redirect(url_for('profile'))

        return render_template(
            'login.html',
            error='Неправильний email або пароль.'
        )

    return render_template('login.html')

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('home'))


@app.route("/profile", methods=["GET", "POST"])
def profile():
    user_id = session.get("user_id")

    if not user_id: # ЗАХИСТ7: доступ дозволено лише авторизованому користувачу
        return redirect(url_for("login"))

    user = db.session.get(User, user_id)

    if not user: # ЗАХИСТ8: перевіряємо, чи існує користувач із цієї сесії
        session.clear()
        return redirect(url_for("login"))

    if request.method == "POST":
        avatar = request.files.get("avatar")

        if not avatar or not avatar.filename:
            return render_template(
                "profile.html",
                user=user,
                error="Спочатку обери фото 💜"
            )

        original_name = secure_filename(avatar.filename)

        if "." not in original_name:
            return render_template(
                "profile.html",
                user=user,
                error="Обери файл PNG, JPG, JPEG, GIF або WEBP."
            )

        extension = original_name.rsplit(".", 1)[1].lower()

        if extension not in ALLOWED_EXTENSIONS: # ЗАХИСТ9: дозволяємо завантажувати лише файли з указаними розширеннями
            return render_template(
                "profile.html",
                user=user,
                error="Обери файл PNG, JPG, JPEG, GIF або WEBP."
            )

        avatar_filename = f"{uuid.uuid4().hex}.{extension}"
        avatar_path = os.path.join(
            app.config["UPLOAD_FOLDER"],
            avatar_filename
        )

        avatar.save(avatar_path)

        user.avatar_filename = avatar_filename
        db.session.commit()

        return redirect(url_for("profile"))

    return render_template("profile.html", user=user)


@app.route("/")
@app.route("/home")
def home():
    posts = Post.query.order_by(Post.id.desc()).all()
    user_id = session.get("user_id")

    return render_template(
        "home.html",
        posts=posts,
        logged_in=user_id is not None
    )

@app.route("/new_post", methods=["GET", "POST"])
def new_post():
    user_id = session.get("user_id")

    if not user_id: # ЗАХИСТ7: доступ дозволено лише авторизованому користувачу
        return redirect(url_for("login"))

    user = db.session.get(User, user_id)

    if not user: # ЗАХИСТ8: перевіряємо, чи існує користувач із цієї сесії
        session.clear()
        return redirect(url_for("login"))

    if request.method == "POST":
        content = request.form.get("content", "").strip()
        image = request.files.get("image")
        image_filename = None

        if not content:
            return render_template(
                "new_post.html",
                error="Напиши щось для свого допису 💜"
            )

        if image and image.filename:
            original_name = secure_filename(image.filename)
            extension = original_name.rsplit(".", 1)[-1].lower()

            if "." not in original_name or extension not in ALLOWED_EXTENSIONS: # ЗАХИСТ10: перевіряємо розширення картинки перед збереженням
                return render_template(
                    "new_post.html",
                    error="Обери картинку PNG, JPG, JPEG, GIF або WEBP."
                )

            image_filename = f"{uuid.uuid4().hex}.{extension}" # ЗАХИСТ12: генеруємо випадкову назву для картинки допису
            image.save(os.path.join(
                app.config["UPLOAD_FOLDER"], image_filename
            ))

        post = Post(
            title="",
            content=content,
            user_id=user.id,
            image_filename=image_filename
        )

        db.session.add(post)
        db.session.commit()

        return redirect(url_for("home"))

    return render_template("new_post.html")

@app.route("/delete_post/<int:post_id>", methods=["POST"])
def delete_post(post_id):
    user_id = session.get("user_id")

    if not user_id: # ЗАХИСТ14: не дозволяємо неавторизованим користувачам видаляти дописи
        return redirect(url_for("login"))

    post = db.session.get(Post, post_id)

    if not post:
        return redirect(url_for("home"))

    # Видаляти допис може тільки його автор
    if post.user_id != user_id:
        return redirect(url_for("home"))

    # Видаляємо файл картинки, якщо він є
    if post.image_filename:
        image_path = os.path.join(
            app.config["UPLOAD_FOLDER"],
            post.image_filename
        )

        if os.path.isfile(image_path):
            os.remove(image_path)

    db.session.delete(post)
    db.session.commit()

    return redirect(url_for("home"))


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    avatar_filename = db.Column(db.String(255), nullable=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False, default="")
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(
        db.Integer, db.ForeignKey("user.id"), nullable=False
    )

    image_filename = db.Column(db.String(255), nullable=True) # ЗАХИСТ12: генеруємо випадкову назву для картинки допису
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    author = db.relationship("User", backref="posts")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()

        # Перевіряємо колонки таблиці post
        post_columns = {
            column["name"]
            for column in inspect(db.engine).get_columns("post")
        }

        # Перевіряємо колонки таблиці user
        user_columns = {
            column["name"]
            for column in inspect(db.engine).get_columns("user")
        }

        with db.engine.begin() as connection:
            if "image_filename" not in post_columns:
                connection.execute(text(
                    "ALTER TABLE post ADD COLUMN image_filename VARCHAR(255)"
                ))

            if "created_at" not in post_columns:
                connection.execute(text(
                    "ALTER TABLE post ADD COLUMN created_at DATETIME"
                ))

            if "avatar_filename" not in user_columns:
                connection.execute(text(
                    "ALTER TABLE user ADD COLUMN avatar_filename VARCHAR(255)"
                ))

    app.run(debug=True)
