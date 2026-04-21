import os
from flask import Flask, request
from flask_login import LoginManager
from utils.logger import configure_logging
from config import Config
from models import User, db
from services.database import init_db

# Import Blueprints
from routes.main import main_bp
from routes.auth import auth_bp
from routes.scan import scan_bp
from routes.report import report_bp
from routes.user import user_bp
from webhook import webhook_bp

def create_app():
    # Setup App
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize Logger
    configure_logging()

    # Initialize Database
    init_db(app)

    # Auto-Migration for Production (Fixes Password Length)
    with app.app_context():
        from sqlalchemy import text
        try:
            # Try to alter columns for Postgres (Render default)
            db.session.execute(text('ALTER TABLE "user" ALTER COLUMN password TYPE VARCHAR(255);'))
            db.session.commit()
            print("Database migration: Expanded password column successfully.")
        except Exception as e:
            db.session.rollback()
            # If it's SQLite or already fixed, this might fail, which is fine
            print(f"Database migration info: {e}")

    # Security Headers Hook
    @app.after_request
    def set_security_headers(response):
        """Native Python implementation of Helmet.js security practices"""
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    # Initialize Login Manager
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # Register Blueprints
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(report_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(webhook_bp)

    return app

app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
