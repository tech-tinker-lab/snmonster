"""
Migration script to add categories table and category_id foreign key to devices table.
"""
import sqlite3

def migrate(db_path="network_admin.db"):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    # Create categories table if not exists
    c.execute('''
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT
        )
    ''')
    # Add category_id column to devices if not exists
    c.execute("PRAGMA table_info(devices)")
    columns = [row[1] for row in c.fetchall()]
    if "category_id" not in columns:
        c.execute("ALTER TABLE devices ADD COLUMN category_id INTEGER REFERENCES categories(id)")
    conn.commit()
    conn.close()
    print("Migration complete: categories table and category_id column added.")

if __name__ == "__main__":
    migrate()
