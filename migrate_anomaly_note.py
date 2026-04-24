import pyodbc
from config import get_connection

def migrate():
    conn = get_connection()
    if not conn:
        print("Could not connect to database.")
        return
    
    try:
        cursor = conn.cursor()
        # Add response_note column to anomaly_flags
        print("Migrating anomaly_flags: Adding response_note column...")
        cursor.execute("ALTER TABLE anomaly_flags ADD response_note NVARCHAR(500) NULL")
        conn.commit()
        print("Migration successful.")
    except Exception as e:
        if "already exists" in str(e) or "42S21" in str(e):
            print("Column response_note already exists, skipping.")
        else:
            print(f"Migration error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    migrate()
