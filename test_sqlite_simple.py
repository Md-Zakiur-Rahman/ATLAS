import sqlite3
import os

print("Testing SQLite...")

# Create logs folder
os.makedirs("D:\\logs", exist_ok=True)

# Connect to database
db = sqlite3.connect("D:\\logs\\test.db")
cursor = db.cursor()

# Create test table
cursor.execute("""
    CREATE TABLE test (
        id INTEGER PRIMARY KEY,
        name TEXT
    )
""")

# Insert data
cursor.execute("INSERT INTO test (name) VALUES ('SQLite Works!')")
db.commit()

# Read data
cursor.execute("SELECT * FROM test")
result = cursor.fetchone()

print(f"✓ SQLite is working! Result: {result}")

db.close()

# Cleanup
os.remove("D:\\logs\\test.db")
