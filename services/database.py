from models import db

def init_db(app):
    """
    Initialize SQLAlchemy with the Flask App context
    """
    db.init_app(app)
    with app.app_context():
        db.create_all()
