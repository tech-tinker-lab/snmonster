#!/usr/bin/env python3
"""
Database migration script to add is_managed column to devices table
"""

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database import get_db, engine
from sqlalchemy import text

def migrate_add_is_managed_column():
    """Add is_managed column to devices table"""
    try:
        with engine.connect() as connection:
            # Check if column already exists
            result = connection.execute(text("""
                SELECT COUNT(*) FROM pragma_table_info('devices') 
                WHERE name='is_managed';
            """))
            column_exists = result.scalar() > 0
            
            if not column_exists:
                print("Adding is_managed column to devices table...")
                connection.execute(text("""
                    ALTER TABLE devices 
                    ADD COLUMN is_managed BOOLEAN DEFAULT 0;
                """))
                connection.commit()
                print("Successfully added is_managed column to devices table")
            else:
                print("is_managed column already exists in devices table")
                
    except Exception as e:
        print(f"Error during migration: {e}")
        raise

if __name__ == "__main__":
    print("Running database migration...")
    migrate_add_is_managed_column()
    print("Migration completed!")
