from app import app
from models import db
from sqlalchemy import text

def repair_db():
    with app.app_context():
        print("Starting database repair...")
        try:
            # This handles Postgres on Render
            db.session.execute(text('ALTER TABLE "user" ALTER COLUMN password TYPE VARCHAR(255);'))
            db.session.commit()
            print("Successfully updated password column length in Postgres.")
        except Exception as e:
            db.session.rollback()
            print(f"Postgres update skipped or failed (might be using SQLite): {e}")
            
            # This handles SQLite
            try:
                # SQLite doesn't support ALTER COLUMN TYPE easily, 
                # but we can try to add columns if they are missing
                db.create_all()
                print("Database tables created/verified via create_all().")
            except Exception as e2:
                print(f"SQLite/General error: {e2}")

if __name__ == "__main__":
    repair_db()
