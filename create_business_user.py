import string
import random
from werkzeug.security import generate_password_hash
from app import app
from models import db
from models import User

def generate_password(length=12):
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(random.choice(chars) for _ in range(length))

def create_user():
    with app.app_context():
        username = "admin_business"
        password = "VulnixBizElite2026!"
        
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(username=username, password=generate_password_hash(password, method='scrypt'), tier="Business")
            db.session.add(user)
        else:
            user.password = generate_password_hash(password, method='scrypt')
            user.tier = "Business"
            
        db.session.commit()
        print(f"Business User Created/Updated:")
        print(f"Username: {username}")
        print(f"Password: {password}")

if __name__ == "__main__":
    create_user()
