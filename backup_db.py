import os
import shutil
from datetime import datetime

DB_PATH = os.environ.get(
    "DB_PATH",
    os.path.join(os.path.dirname(__file__), "db.sqlite")
)

BACKUP_DIR = os.path.join(os.path.dirname(__file__), "backups")


def main():
    if not os.path.exists(DB_PATH):
        print(f"Базу не знайдено: {DB_PATH}")
        return

    os.makedirs(BACKUP_DIR, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_name = f"db_backup_{ts}.sqlite"
    backup_path = os.path.join(BACKUP_DIR, backup_name)

    shutil.copy2(DB_PATH, backup_path)
    print(f"Бекап створено: {backup_path}")


if __name__ == "__main__":
    main()
