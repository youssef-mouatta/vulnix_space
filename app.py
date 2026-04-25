import os
from flask import Flask, request
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import import_string

from utils.logger import configure_logging, get_logger
from config import DevelopmentConfig, ProductionConfig, assert_production_safe
from models import User, db
from services.database import init_db

from routes.main import main_bp
from routes.auth import auth_bp
from routes.scan import scan_bp
from routes.report import report_bp
from routes.user import user_bp
from webhook import webhook_bp

csrf = CSRFProtect()
logger = get_logger(__name__)


def create_app(config_object=None):
    app = Flask(__name__)

    if config_object is None:
        env = os.environ.get("FLASK_ENV", "development").lower()
        config_object = ProductionConfig if env == "production" else DevelopmentConfig
    if isinstance(config_object, str):
        config_object = import_string(config_object)

    assert_production_safe(config_object)
    app.config.from_object(config_object)
    if app.config.get("TESTING"):
        app.config["WTF_CSRF_ENABLED"] = False

    configure_logging()

    init_db(app)

    with app.app_context():
        from sqlalchemy import text

        try:
            if "postgresql" in str(db.engine.url):
                db.session.execute(
                    text('ALTER TABLE "user" ALTER COLUMN password TYPE VARCHAR(255);')
                )
                db.session.commit()
                logger.info("Database migration: expanded password column (Postgres).")
        except Exception as e:
            db.session.rollback()
            logger.info("Database migration skipped or already applied: %s", e)

    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        return response

    csrf.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = "auth.login"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(report_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(webhook_bp)

    from webhook import stripe_webhook

    csrf.exempt(stripe_webhook)

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
