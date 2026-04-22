from app import app
from models import db, User

def list_special_users():
    with app.app_context():
        users = User.query.filter(User.tier != 'Free').all()
        if not users:
            print("No Pro or Business users found.")
        else:
            print("Special Users Found:")
            for user in users:
                print(f"Username: {user.username} | Tier: {user.tier} | Email: {user.email}")

if __name__ == "__main__":
    list_special_users()
