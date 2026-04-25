import os
from dotenv import load_dotenv

load_dotenv()

# Dev-only default; production refuses to start with this value (see create_app).
_DEFAULT_DEV_SECRET = "super-secret-saas-key-change-in-prod"


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", _DEFAULT_DEV_SECRET)
    TESTING = False

    database_url = os.getenv("DATABASE_URL", "sqlite:///database.db")
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)

    SQLALCHEMY_DATABASE_URI = database_url
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "")
    HF_TOKEN = os.getenv("HF_TOKEN")
    STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
    STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")

    WTF_CSRF_TIME_LIMIT = None


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"


def assert_production_safe(config_class):
    if config_class is not ProductionConfig:
        return
    secret = (os.getenv("SECRET_KEY") or "").strip()
    if not secret or secret == _DEFAULT_DEV_SECRET:
        raise RuntimeError(
            "FLASK_ENV=production requires SECRET_KEY to be set to a strong, unique value "
            "(not the development placeholder)."
        )
