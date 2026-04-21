import sqlite3
import os

if os.path.exists('instance/database.db'):
    conn = sqlite3.connect('instance/database.db')
else:
    conn = sqlite3.connect('database.db')

cursor = conn.cursor()

try:
    cursor.execute("ALTER TABLE user ADD COLUMN tier VARCHAR(20) DEFAULT 'Free'")
    print("Added tier to user")
except sqlite3.OperationalError as e:
    print("Error (tier probably exists):", e)

try:
    cursor.execute("ALTER TABLE user ADD COLUMN api_key VARCHAR(100)")
    print("Added api_key to user")
except sqlite3.OperationalError as e:
    print("Error (api_key probably exists):", e)

try:
    cursor.execute("ALTER TABLE scan_result ADD COLUMN is_public BOOLEAN DEFAULT 0")
    print("Added is_public to scan_result")
except sqlite3.OperationalError as e:
    print("Error (is_public probably exists):", e)

try:
    cursor.execute("ALTER TABLE scan_result ADD COLUMN explanation_json TEXT")
    print("Added explanation_json to scan_result")
except sqlite3.OperationalError as e:
    print("Error (explanation_json probably exists):", e)

try:
    cursor.execute("ALTER TABLE user ADD COLUMN email VARCHAR(255)")
    print("Added email to user")
except sqlite3.OperationalError as e:
    print("Error (email probably exists):", e)

conn.commit()
conn.close()
