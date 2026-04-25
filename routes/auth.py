import re
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User
from utils.logger import get_logger

auth_bp = Blueprint('auth', __name__)
logger = get_logger(__name__)


def is_valid_email(email):
    if not email or not isinstance(email, str):
        return False
    email = email.strip().lower()
    return bool(
        re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email)
    )


def is_valid_username(username):
    # 4-20 characters, alphanumeric and underscore
    return re.match(r"^[a-zA-Z0-9_]{4,20}$", username)

def is_valid_password(password):
    # At least 8 characters, 1 number, 1 special character
    if len(password) < 8:
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        if not username or not password:
            flash("Please enter both username and password.")
            return redirect(url_for("auth.login"))
            
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            next_page = request.args.get("next")
            if next_page and next_page.startswith("/"):
                return redirect(next_page)
            return redirect(url_for("user.dashboard"))
        else:
            flash("Invalid credentials.")
            
    return render_template("login.html")

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not username or not password or not email:
            flash("Username, email, and password are required.")
            return redirect(url_for("auth.register"))

        if not is_valid_email(email):
            flash("Please enter a valid email address.")
            return redirect(url_for("auth.register"))

        if not is_valid_username(username):
            flash("Username must be 4-20 characters and alphanumeric.")
            return redirect(url_for("auth.register"))

        if not is_valid_password(password):
            flash("Password must be 8+ characters and contain at least one digit and one special character.")
            return redirect(url_for("auth.register"))

        if User.query.filter_by(username=username).first():
            flash("Username already exists.")
            return redirect(url_for("auth.register"))

        if User.query.filter_by(email=email).first():
            flash("That email is already registered.")
            return redirect(url_for("auth.register"))

        try:
            new_user = User(
                username=username,
                email=email,
                password=generate_password_hash(password, method="scrypt"),
            )
            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)
            return redirect(url_for("user.dashboard"))
        except Exception as e:
            db.session.rollback()
            flash("An error occurred during registration. Please try again.")
            logger.exception("Registration error: %s", e)
            return redirect(url_for("auth.register"))
        
    return render_template("register.html")

@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("main.index"))
