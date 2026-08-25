import sqlite3
import os
import sys
import time
from datetime import datetime

def backup_ledger(db_path: str, backup_dir: str):
    """
    Safely creates a point-in-time backup of the SQLite Audit Ledger
    using the online backup API. This works even while the main API
    server is actively writing to the WAL.
    """
    if not os.path.exists(db_path):
        print(f"Error: Database {db_path} does not exist.")
        sys.exit(1)

    os.makedirs(backup_dir, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    backup_file = os.path.join(backup_dir, f"audit_ledger_backup_{timestamp}.db")
    
    print(f"Starting online backup of {db_path} to {backup_file}...")
    start_time = time.time()
    
    try:
        # Connect to existing DB
        source = sqlite3.connect(db_path)
        
        # Connect to new backup DB
        dest = sqlite3.connect(backup_file)
        
        # Perform the online backup
        with dest:
            source.backup(dest, pages=256, sleep=0.01)
            
        source.close()
        dest.close()
        
        duration = time.time() - start_time
        print(f"Backup completed successfully in {duration:.2f} seconds.")
        print(f"Backup file size: {os.path.getsize(backup_file) / 1024:.2f} KB")
        
    except sqlite3.Error as e:
        print(f"SQLite error during backup: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error during backup: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Use config paths if possible, else defaults
    try:
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
        from config import settings
        db_path = settings.DB_PATH
    except ImportError:
        db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'data', 'audit_ledger.db'))
        
    backup_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'data', 'backups'))
    backup_ledger(db_path, backup_dir)
