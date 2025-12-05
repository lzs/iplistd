"""
Database migration script to add api_key_id column to ip_filters table.
"""
from sqlalchemy import create_engine, Column, Integer
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError

DATABASE_URL = "sqlite:///./ip_filter.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

def add_api_key_id_column(engine: Engine):
    from sqlalchemy import text
    with engine.connect() as conn:
        try:
            # Check if column already exists
            result = conn.execute(text("PRAGMA table_info(ip_filters);"))
            columns = [row[1] for row in result]
            if "api_key_id" in columns:
                print("api_key_id column already exists.")
                return
            # Add the column
            conn.execute(text("ALTER TABLE ip_filters ADD COLUMN api_key_id INTEGER;"))
            print("api_key_id column added.")
        except OperationalError as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    add_api_key_id_column(engine)
