from app import app
from models import db
from sqlalchemy import text

def repair_db():
    with app.app_context():
        print("Starting comprehensive database repair...")
        from sqlalchemy import text
        
        # 1. Attempt Postgres-specific 'IF NOT EXISTS' migrations
        try:
            if db.engine.url.drivername.startswith("postgresql"):
                db.session.execute(text('ALTER TABLE "user" ALTER COLUMN password TYPE VARCHAR(255);'))
                db.session.execute(text('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS tier VARCHAR(20) DEFAULT \'Free\';'))
                db.session.execute(text('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS api_key VARCHAR(100) UNIQUE;'))
                db.session.execute(text('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS email VARCHAR(255) UNIQUE;'))
                db.session.execute(text('ALTER TABLE scan_result ADD COLUMN IF NOT EXISTS is_public BOOLEAN DEFAULT FALSE;'))
                db.session.execute(text('ALTER TABLE scan_result ADD COLUMN IF NOT EXISTS explanation_json TEXT;'))
                db.session.commit()
                print("Successfully updated Postgres schema.")
        except Exception as e:
            db.session.rollback()
            print(f"Postgres-specific migration skipped or failed: {e}")

        # 2. Universal create_all (creates missing tables, but not missing columns in SQLite)
        try:
            db.create_all()
            print("Base tables verified.")
        except Exception as e:
            print(f"Error during create_all: {e}")

        # 3. Manual SQLite migration fallback for missing columns
        if not db.engine.url.drivername.startswith("postgresql"):
            print("Checking SQLite for missing columns...")
            for cmd in [
                "ALTER TABLE user ADD COLUMN tier VARCHAR(20) DEFAULT 'Free'",
                "ALTER TABLE user ADD COLUMN api_key VARCHAR(100)",
                "ALTER TABLE user ADD COLUMN email VARCHAR(255)",
                "ALTER TABLE scan_result ADD COLUMN is_public BOOLEAN DEFAULT 0",
                "ALTER TABLE scan_result ADD COLUMN explanation_json TEXT"
            ]:
                try:
                    db.session.execute(text(cmd))
                    db.session.commit()
                    print(f"Executed: {cmd}")
                except Exception:
                    db.session.rollback()
        
        print("Repair process complete.")

if __name__ == "__main__":
    repair_db()
