import os
import sqlite3
import secrets
import csv
import logging
from datetime import datetime
from io import BytesIO, StringIO
from functools import wraps
from zoneinfo import ZoneInfo

from flask import (
    Flask, g, render_template, request, redirect, url_for,
    send_file, abort, flash, Response, session
)
import qrcode
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "very-secret-key-change-me")

# Початковий адмін (буде створений у таблиці users, якщо її ще немає записів is_admin=1)
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin")

TIMEZONE_NAME = os.environ.get("TIMEZONE", "Europe/Kyiv")
LOCAL_TZ = ZoneInfo(TIMEZONE_NAME)
UTC_TZ = ZoneInfo("UTC")

DB_PATH = os.environ.get(
    "DB_PATH",
    os.path.join(os.path.dirname(__file__), "db.sqlite")
)

LOG_PATH = os.environ.get(
    "LOG_PATH",
    os.path.join(os.path.dirname(__file__), "app.log")
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_PATH, encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# ----------------- Робота з базою даних -----------------


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def add_column_if_not_exists(table: str, column_def: str):
    db = get_db()
    col_name = column_def.split()[0]
    rows = db.execute(f"PRAGMA table_info({table});").fetchall()
    col_names = [r["name"] for r in rows]
    if col_name not in col_names:
        db.execute(f"ALTER TABLE {table} ADD COLUMN {column_def};")
        db.commit()
        logger.info(f"ALTER TABLE {table} ADD COLUMN {column_def};")


def init_db():
    db = get_db()
    cursor = db.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS materials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            unit TEXT NOT NULL
        );
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS locations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
        );
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS workers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            pin TEXT
        );
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS containers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            material_id INTEGER NOT NULL,
            location_id INTEGER NOT NULL,
            qr_token TEXT NOT NULL UNIQUE,
            min_balance REAL,
            FOREIGN KEY(material_id) REFERENCES materials(id),
            FOREIGN KEY(location_id) REFERENCES locations(id)
        );
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            worker_id INTEGER,
            container_id INTEGER NOT NULL,
            qty REAL NOT NULL,
            direction TEXT NOT NULL CHECK(direction IN ('IN','OUT')),
            job TEXT,
            FOREIGN KEY(worker_id) REFERENCES workers(id),
            FOREIGN KEY(container_id) REFERENCES containers(id)
        );
        """
    )

    # Облікові записи (адмін + працівники)
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            worker_id INTEGER,
            FOREIGN KEY(worker_id) REFERENCES workers(id)
        );
        """
    )

    db.commit()

    add_column_if_not_exists("containers", "min_balance REAL")
    add_column_if_not_exists("workers", "pin TEXT")

    # Унікальність PIN
    try:
        db.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_workers_pin ON workers(pin);"
        )
        db.commit()
    except sqlite3.OperationalError:
        logger.warning("Не вдалося створити індекс для workers.pin")

    # Індекси для операцій
    try:
        db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_tx_container_created_at
            ON transactions(container_id, created_at);
            """
        )
        db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_tx_worker_created_at
            ON transactions(worker_id, created_at);
            """
        )
        db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_tx_direction_created_at
            ON transactions(direction, created_at);
            """
        )
        db.commit()
    except sqlite3.OperationalError:
        logger.warning("Не вдалося створити індекси для transactions")

    # Унікальний логін на працівника (необовʼязково)
    try:
        db.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_worker_id ON users(worker_id) "
            "WHERE worker_id IS NOT NULL;"
        )
        db.commit()
    except sqlite3.OperationalError:
        logger.warning("Не вдалося створити індекс для users.worker_id")

    # Створення дефолтного адміністратора, якщо ще нема
    row = db.execute(
        "SELECT COUNT(*) AS cnt FROM users WHERE is_admin = 1;"
    ).fetchone()
    if row["cnt"] == 0:
        pw_hash = generate_password_hash(ADMIN_PASSWORD)
        db.execute(
            "INSERT INTO users (username, password_hash, is_admin, worker_id) "
            "VALUES (?, ?, 1, NULL);",
            (ADMIN_USERNAME, pw_hash),
        )
        db.commit()
        logger.info(
            f"Створено початковий адмін-акаунт '{ADMIN_USERNAME}' "
            f"зі стандартним паролем (змінити в інтерфейсі)."
        )


with app.app_context():
    init_db()


# ----------------- Аутентифікація -----------------


def login_required(view):
    """Доступ тільки для адмінів."""
    @wraps(view)
    def wrapped_view(**kwargs):
        if not session.get("user_id") or not session.get("is_admin"):
            return redirect(url_for("login", next=request.path))
        return view(**kwargs)
    return wrapped_view


@app.route("/")
def index():
    """Головна:
       - адміна перекидає на дашборд,
       - працівнику показує просту сторінку з інструкцією,
       - неавторизованому теж інструкцію.
    """
    if session.get("is_admin"):
        return redirect(url_for("admin_index"))
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    db = get_db()

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        user = db.execute(
            "SELECT * FROM users WHERE username = ?;",
            (username,),
        ).fetchone()

        if not user or not check_password_hash(user["password_hash"], password):
            flash("Невірний логін або пароль.", "error")
            logger.warning(f"Login FAILED for user '{username}' from {request.remote_addr}")
            return redirect(url_for("login"))

        # Успішний вхід
        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["is_admin"] = bool(user["is_admin"])
        session["worker_id"] = user["worker_id"]

        logger.info(
            f"Login success: username={user['username']} "
            f"is_admin={user['is_admin']} from {request.remote_addr}"
        )
        flash("Вхід виконано.", "success")

        next_url = request.args.get("next")

        if user["is_admin"]:
            if not next_url or not next_url.startswith("/admin"):
                next_url = url_for("admin_index")
        else:
            # Звичайний працівник: або повертаємось на потрібну сторінку, або на головну
            if not next_url:
                next_url = url_for("index")

        return redirect(next_url)

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Ви вийшли з системи.", "success")
    return redirect(url_for("login"))


# ----------------- Допоміжні функції -----------------


def get_materials():
    db = get_db()
    return db.execute("SELECT * FROM materials ORDER BY code;").fetchall()


def get_locations():
    db = get_db()
    return db.execute("SELECT * FROM locations ORDER BY name;").fetchall()


def get_workers():
    """
    Працівники + (якщо є) привʼязаний логін.
    """
    db = get_db()
    return db.execute(
        """
        SELECT
            w.*,
            (
                SELECT username FROM users u
                WHERE u.worker_id = w.id
                LIMIT 1
            ) AS username
        FROM workers w
        ORDER BY w.name;
        """
    ).fetchall()


def get_containers_with_stock(location_id=None, search=None):
    db = get_db()
    conditions = []
    params = []

    if location_id:
        conditions.append("c.location_id = ?")
        params.append(location_id)

    if search:
        pattern = f"%{search}%"
        conditions.append(
            "("
            "m.code LIKE ? OR "
            "m.name LIKE ? OR "
            "l.name LIKE ?"
            ")"
        )
        params.extend([pattern, pattern, pattern])

    where_clause = ""
    if conditions:
        where_clause = "WHERE " + " AND ".join(conditions)

    query = f"""
        SELECT
            c.id,
            c.location_id,
            c.qr_token,
            c.min_balance,
            m.code AS material_code,
            m.name AS material_name,
            m.unit AS material_unit,
            l.name AS location_name,
            COALESCE(SUM(
                CASE
                    WHEN t.direction = 'IN' THEN t.qty
                    WHEN t.direction = 'OUT' THEN -t.qty
                END
            ), 0) AS balance
        FROM containers c
        JOIN materials m ON c.material_id = m.id
        JOIN locations l ON c.location_id = l.id
        LEFT JOIN transactions t ON t.container_id = c.id
        {where_clause}
        GROUP BY
            c.id,
            c.location_id,
            c.qr_token,
            c.min_balance,
            m.code,
            m.name,
            m.unit,
            l.name
        ORDER BY m.code, l.name;
    """
    return db.execute(query, params).fetchall()


def get_materials_stock():
    db = get_db()
    return db.execute(
        """
        SELECT
            m.id,
            m.code,
            m.name,
            m.unit,
            COALESCE(SUM(
                CASE
                    WHEN t.direction = 'IN' THEN t.qty
                    WHEN t.direction = 'OUT' THEN -t.qty
                END
            ), 0) AS balance
        FROM materials m
        LEFT JOIN containers c ON c.material_id = m.id
        LEFT JOIN transactions t ON t.container_id = c.id
        GROUP BY m.id, m.code, m.name, m.unit
        ORDER BY m.code;
        """
    ).fetchall()


@app.template_filter("localtime")
def localtime_filter(value: str) -> str:
    if not value:
        return ""
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return value
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC_TZ)
    dt_local = dt.astimezone(LOCAL_TZ)
    return dt_local.strftime("%Y-%m-%d %H:%M")


# ----------------- Дашборд -----------------


@app.route("/admin")
@login_required
def admin_index():
    locations = get_locations()
    containers = get_containers_with_stock()

    shelves = []
    for loc in locations:
        shelf_containers = [c for c in containers if c["location_name"] == loc["name"]]
        has_low = any(
            c["min_balance"] is not None and c["balance"] < c["min_balance"]
            for c in shelf_containers
        )
        shelves.append(
            {
                "location": loc,
                "containers": shelf_containers,
                "has_low": has_low,
            }
        )

    return render_template("admin_index.html", shelves=shelves)


@app.route("/admin/backup")
@login_required
def download_backup():
    if not os.path.exists(DB_PATH):
        flash("Файл бази даних не знайдено.", "error")
        return redirect(url_for("admin_index"))

    logger.info("Admin downloaded DB backup.")
    return send_file(
        DB_PATH,
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name="workshop-db.sqlite",
    )


# ----------------- Налаштування акаунта (зміна пароля адміна) -----------------


@app.route("/admin/account", methods=["GET", "POST"])
@login_required
def admin_account():
    db = get_db()
    user_id = session.get("user_id")
    user = db.execute(
        "SELECT * FROM users WHERE id = ?;",
        (user_id,),
    ).fetchone()

    if user is None:
        flash("Користувача не знайдено.", "error")
        return redirect(url_for("admin_index"))

    if request.method == "POST":
        current_password = request.form.get("current_password", "").strip()
        new_password = request.form.get("new_password", "").strip()
        new_password2 = request.form.get("new_password2", "").strip()

        if not current_password or not new_password or not new_password2:
            flash("Заповніть всі поля.", "error")
            return redirect(url_for("admin_account"))

        if not check_password_hash(user["password_hash"], current_password):
            flash("Невірний поточний пароль.", "error")
            return redirect(url_for("admin_account"))

        if new_password != new_password2:
            flash("Нові паролі не співпадають.", "error")
            return redirect(url_for("admin_account"))

        pw_hash = generate_password_hash(new_password)
        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?;",
            (pw_hash, user_id),
        )
        db.commit()
        flash("Пароль успішно змінено.", "success")
        return redirect(url_for("admin_index"))

    return render_template("admin_account.html", user=user)


# ----------------- Матеріали -----------------


@app.route("/admin/materials", methods=["GET", "POST"])
@login_required
def admin_materials():
    db = get_db()

    if request.method == "POST":
        action = request.form.get("action", "add")

        if action == "add":
            name = request.form.get("name", "").strip()
            unit = request.form.get("unit", "").strip()

            if not name or not unit:
                flash("Заповніть всі поля (назва, одиниця).", "error")
            else:
                row = db.execute(
                    "SELECT COALESCE(MAX(CAST(code AS INTEGER)), 0) AS max_code FROM materials;"
                ).fetchone()
                next_code = str((row["max_code"] or 0) + 1)
                try:
                    db.execute(
                        "INSERT INTO materials (code, name, unit) VALUES (?, ?, ?);",
                        (next_code, name, unit),
                    )
                    db.commit()
                    flash(f"Матеріал додано. Код: {next_code}", "success")
                except sqlite3.IntegrityError:
                    flash("Помилка при створенні матеріалу (дублікат коду).", "error")

        elif action == "edit":
            material_id = request.form.get("material_id")
            name = request.form.get("name", "").strip()
            unit = request.form.get("unit", "").strip()

            if not material_id or not name or not unit:
                flash("Заповніть назву та одиницю виміру.", "error")
            else:
                db.execute(
                    "UPDATE materials SET name = ?, unit = ? WHERE id = ?;",
                    (name, unit, material_id),
                )
                db.commit()
                flash("Матеріал оновлено.", "success")

        return redirect(url_for("admin_materials"))

    materials = get_materials()
    return render_template("admin_materials.html", materials=materials)


@app.route("/admin/materials/<int:material_id>/delete", methods=["POST"])
@login_required
def delete_material(material_id):
    db = get_db()
    row = db.execute(
        "SELECT COUNT(*) AS cnt FROM containers WHERE material_id = ?;",
        (material_id,),
    ).fetchone()
    if row["cnt"] > 0:
        flash("Неможливо видалити матеріал: до нього привʼязані ємності.", "error")
        return redirect(url_for("admin_materials"))

    db.execute("DELETE FROM materials WHERE id = ?;", (material_id,))
    db.commit()
    logger.info(f"Deleted material id={material_id}")
    flash("Матеріал видалено.", "success")
    return redirect(url_for("admin_materials"))


# ----------------- Локації -----------------


@app.route("/admin/locations", methods=["GET", "POST"])
@login_required
def admin_locations():
    db = get_db()

    if request.method == "POST":
        action = request.form.get("action", "add")

        if action == "add":
            name = request.form.get("name", "").strip()
            if not name:
                flash("Введіть назву локації.", "error")
            else:
                try:
                    db.execute(
                        "INSERT INTO locations (name) VALUES (?);",
                        (name,),
                    )
                    db.commit()
                    flash("Локацію додано.", "success")
                except sqlite3.IntegrityError:
                    flash("Локація з такою назвою вже існує.", "error")

        elif action == "edit":
            location_id = request.form.get("location_id")
            name = request.form.get("name", "").strip()
            if not location_id or not name:
                flash("Введіть назву локації.", "error")
            else:
                try:
                    db.execute(
                        "UPDATE locations SET name = ? WHERE id = ?;",
                        (name, location_id),
                    )
                    db.commit()
                    flash("Локацію оновлено.", "success")
                except sqlite3.IntegrityError:
                    flash("Локація з такою назвою вже існує.", "error")

        return redirect(url_for("admin_locations"))

    locations = get_locations()
    return render_template("admin_locations.html", locations=locations)


@app.route("/admin/locations/<int:location_id>/delete", methods=["POST"])
@login_required
def delete_location(location_id):
    db = get_db()
    row = db.execute(
        "SELECT COUNT(*) AS cnt FROM containers WHERE location_id = ?;",
        (location_id,),
    ).fetchone()
    if row["cnt"] > 0:
        flash("Неможливо видалити локацію: до неї привʼязані ємності.", "error")
        return redirect(url_for("admin_locations"))

    db.execute("DELETE FROM locations WHERE id = ?;", (location_id,))
    db.commit()
    logger.info(f"Deleted location id={location_id}")
    flash("Локацію видалено.", "success")
    return redirect(url_for("admin_locations"))


# ----------------- Працівники + облікові записи -----------------


@app.route("/admin/workers", methods=["GET", "POST"])
@login_required
def admin_workers():
    db = get_db()

    if request.method == "POST":
        action = request.form.get("action", "add")

        if action == "add":
            name = request.form.get("name", "").strip()
            pin = request.form.get("pin", "").strip() or None

            if not name:
                flash("Введіть імʼя/прізвище працівника.", "error")
            else:
                try:
                    db.execute(
                        "INSERT INTO workers (name, pin) VALUES (?, ?);",
                        (name, pin),
                    )
                    db.commit()
                    flash("Працівника додано.", "success")
                except sqlite3.IntegrityError:
                    flash("Працівник або PIN вже існує.", "error")

        elif action == "update_pin":
            worker_id = request.form.get("worker_id")
            pin = request.form.get("pin", "").strip() or None
            try:
                db.execute(
                    "UPDATE workers SET pin = ? WHERE id = ?;",
                    (pin, worker_id),
                )
                db.commit()
                flash("PIN оновлено.", "success")
            except sqlite3.IntegrityError:
                flash("Такий PIN вже використовується.", "error")

        elif action == "edit_name":
            worker_id = request.form.get("worker_id")
            name = request.form.get("name", "").strip()
            if not worker_id or not name:
                flash("Введіть імʼя/прізвище працівника.", "error")
            else:
                db.execute(
                    "UPDATE workers SET name = ? WHERE id = ?;",
                    (name, worker_id),
                )
                db.commit()
                flash("Імʼя працівника оновлено.", "success")

        elif action == "create_user":
            worker_id = request.form.get("worker_id")
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()

            if not worker_id or not username or not password:
                flash("Для створення логіну заповніть всі поля.", "error")
                return redirect(url_for("admin_workers"))

            existing = db.execute(
                "SELECT id FROM users WHERE worker_id = ?;",
                (worker_id,),
            ).fetchone()
            if existing:
                flash("Для цього працівника вже створено обліковий запис.", "error")
                return redirect(url_for("admin_workers"))

            existing_username = db.execute(
                "SELECT id FROM users WHERE username = ?;",
                (username,),
            ).fetchone()
            if existing_username:
                flash("Такий логін вже використовується.", "error")
                return redirect(url_for("admin_workers"))

            pw_hash = generate_password_hash(password)
            db.execute(
                "INSERT INTO users (username, password_hash, is_admin, worker_id) "
                "VALUES (?, ?, 0, ?);",
                (username, pw_hash, worker_id),
            )
            db.commit()
            flash("Обліковий запис для працівника створено.", "success")

        elif action == "change_user_password":
            worker_id = request.form.get("worker_id")
            password = request.form.get("password", "").strip()

            if not worker_id or not password:
                flash("Введіть новий пароль.", "error")
                return redirect(url_for("admin_workers"))

            user = db.execute(
                "SELECT id FROM users WHERE worker_id = ?;",
                (worker_id,),
            ).fetchone()
            if user is None:
                flash("Для цього працівника немає облікового запису.", "error")
                return redirect(url_for("admin_workers"))

            pw_hash = generate_password_hash(password)
            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?;",
                (pw_hash, user["id"]),
            )
            db.commit()
            flash("Пароль для працівника оновлено.", "success")

        return redirect(url_for("admin_workers"))

    workers = get_workers()
    return render_template("admin_workers.html", workers=workers)


@app.route("/admin/workers/<int:worker_id>/delete", methods=["POST"])
@login_required
def delete_worker(worker_id):
    db = get_db()
    row = db.execute(
        "SELECT COUNT(*) AS cnt FROM transactions WHERE worker_id = ?;",
        (worker_id,),
    ).fetchone()
    if row["cnt"] > 0:
        flash("Неможливо видалити працівника: є повʼязані операції.", "error")
        return redirect(url_for("admin_workers"))

    # Видаляємо привʼязаний користувацький акаунт (якщо є)
    db.execute("DELETE FROM users WHERE worker_id = ?;", (worker_id,))
    db.execute("DELETE FROM workers WHERE id = ?;", (worker_id,))
    db.commit()
    logger.info(f"Deleted worker id={worker_id}")
    flash("Працівника видалено.", "success")
    return redirect(url_for("admin_workers"))


# ----------------- Ємності -----------------


@app.route("/admin/containers", methods=["GET", "POST"])
@login_required
def admin_containers():
    db = get_db()

    if request.method == "POST":
        action = request.form.get("action", "add")

        if action == "add":
            material_id = request.form.get("material_id")
            location_id = request.form.get("location_id")
            min_balance_str = request.form.get("min_balance", "").strip()

            if not material_id or not location_id:
                flash("Оберіть матеріал і локацію.", "error")
            else:
                min_balance = None
                if min_balance_str:
                    try:
                        min_balance = float(min_balance_str.replace(",", "."))
                    except ValueError:
                        flash("Мінімальний залишок має бути числом.", "error")
                        return redirect(url_for("admin_containers"))

                qr_token = secrets.token_urlsafe(16)
                db.execute(
                    """
                    INSERT INTO containers (material_id, location_id, qr_token, min_balance)
                    VALUES (?, ?, ?, ?);
                    """,
                    (material_id, location_id, qr_token, min_balance),
                )
                db.commit()
                flash("Ємність створено. Можна друкувати QR-код.", "success")

        elif action == "update_min":
            container_id = request.form.get("container_id")
            min_balance_str = request.form.get("min_balance", "").strip()

            min_balance = None
            if min_balance_str:
                try:
                    min_balance = float(min_balance_str.replace(",", "."))
                except ValueError:
                    flash("Мінімальний залишок має бути числом.", "error")
                    return redirect(url_for("admin_containers"))

            db.execute(
                "UPDATE containers SET min_balance = ? WHERE id = ?;",
                (min_balance, container_id),
            )
            db.commit()
            flash("Мінімальний залишок оновлено.", "success")

        elif action == "update_location":
            container_id = request.form.get("container_id")
            location_id = request.form.get("location_id")
            if not container_id or not location_id:
                flash("Оберіть локацію для оновлення.", "error")
            else:
                db.execute(
                    "UPDATE containers SET location_id = ? WHERE id = ?;",
                    (location_id, container_id),
                )
                db.commit()
                flash("Локацію ємності оновлено.", "success")

        return redirect(url_for("admin_containers"))

    location_filter = request.args.get("location_id") or None
    search_q = request.args.get("q") or None

    materials = get_materials()
    locations = get_locations()
    containers = get_containers_with_stock(location_filter, search_q)

    selected_location_id = int(location_filter) if location_filter else None

    return render_template(
        "admin_containers.html",
        materials=materials,
        locations=locations,
        containers=containers,
        selected_location_id=selected_location_id,
        search_q=search_q,
    )


@app.route("/admin/containers/<int:container_id>/delete", methods=["POST"])
@login_required
def delete_container(container_id):
    db = get_db()
    row = db.execute(
        "SELECT COUNT(*) AS cnt FROM transactions WHERE container_id = ?;",
        (container_id,),
    ).fetchone()
    if row["cnt"] > 0:
        flash("Неможливо видалити ємність: є повʼязані операції.", "error")
        return redirect(url_for("admin_containers"))

    db.execute("DELETE FROM containers WHERE id = ?;", (container_id,))
    db.commit()
    logger.info(f"Deleted container id={container_id}")
    flash("Ємність видалено.", "success")
    return redirect(url_for("admin_containers"))


# ----------------- Історія по ємності -----------------


@app.route("/admin/containers/<int:container_id>/history")
@login_required
def container_history(container_id):
    db = get_db()

    container = db.execute(
        """
        SELECT
            c.id AS container_id,
            c.min_balance,
            m.code AS material_code,
            m.name AS material_name,
            m.unit AS material_unit,
            l.name AS location_name,
            COALESCE(SUM(
                CASE
                    WHEN t2.direction = 'IN' THEN t2.qty
                    WHEN t2.direction = 'OUT' THEN -t2.qty
                END
            ), 0) AS balance
        FROM containers c
        JOIN materials m ON c.material_id = m.id
        JOIN locations l ON c.location_id = l.id
        LEFT JOIN transactions t2 ON t2.container_id = c.id
        WHERE c.id = ?
        GROUP BY c.id, c.min_balance, m.code, m.name, m.unit, l.name;
        """,
        (container_id,),
    ).fetchone()

    if container is None:
        abort(404)

    date_from = request.args.get("date_from") or None
    date_to = request.args.get("date_to") or None
    direction = request.args.get("direction") or None
    worker_id = request.args.get("worker_id") or None

    conditions = ["t.container_id = ?"]
    params = [container_id]

    if direction in ("IN", "OUT"):
        conditions.append("t.direction = ?")
        params.append(direction)

    if worker_id:
        conditions.append("t.worker_id = ?")
        params.append(worker_id)

    if date_from:
        conditions.append("t.created_at >= ?")
        params.append(date_from + "T00:00:00")

    if date_to:
        conditions.append("t.created_at <= ?")
        params.append(date_to + "T23:59:59")

    where_clause = "WHERE " + " AND ".join(conditions)

    history_rows = db.execute(
        f"""
        SELECT
            t.id,
            t.created_at,
            t.qty,
            t.direction,
            t.job,
            w.name AS worker_name
        FROM transactions t
        LEFT JOIN workers w ON t.worker_id = w.id
        {where_clause}
        ORDER BY t.created_at DESC;
        """,
        params,
    ).fetchall()

    workers = get_workers()
    selected_worker_id = int(worker_id) if worker_id else None

    filters = {
        "date_from": date_from,
        "date_to": date_to,
        "direction": direction,
        "worker_id": worker_id,
    }

    return render_template(
        "admin_container_history.html",
        container=container,
        history_rows=history_rows,
        workers=workers,
        filters=filters,
        selected_worker_id=selected_worker_id,
    )


@app.route("/admin/containers/<int:container_id>/history/export")
@login_required
def export_container_history(container_id):
    db = get_db()

    exists = db.execute(
        "SELECT 1 FROM containers WHERE id = ?;",
        (container_id,),
    ).fetchone()
    if exists is None:
        abort(404)

    date_from = request.args.get("date_from") or None
    date_to = request.args.get("date_to") or None
    direction = request.args.get("direction") or None
    worker_id = request.args.get("worker_id") or None

    conditions = ["t.container_id = ?"]
    params = [container_id]

    if direction in ("IN", "OUT"):
        conditions.append("t.direction = ?")
        params.append(direction)

    if worker_id:
        conditions.append("t.worker_id = ?")
        params.append(worker_id)

    if date_from:
        conditions.append("t.created_at >= ?")
        params.append(date_from + "T00:00:00")

    if date_to:
        conditions.append("t.created_at <= ?")
        params.append(date_to + "T23:59:59")

    where_clause = "WHERE " + " AND ".join(conditions)

    query = f"""
        SELECT
            t.id,
            t.created_at,
            t.direction,
            t.qty,
            t.job,
            w.name AS worker_name,
            m.code AS material_code,
            m.name AS material_name,
            m.unit AS material_unit,
            l.name AS location_name
        FROM transactions t
        JOIN containers c ON t.container_id = c.id
        JOIN materials m ON c.material_id = m.id
        JOIN locations l ON c.location_id = l.id
        LEFT JOIN workers w ON t.worker_id = w.id
        {where_clause}
        ORDER BY t.created_at DESC;
    """

    rows = db.execute(query, params).fetchall()

    output = StringIO()
    writer = csv.writer(output, delimiter=";")

    writer.writerow([
        "ID",
        "Дата/час (локальний)",
        "Тип (IN/OUT)",
        "Працівник",
        "Матеріал (код)",
        "Матеріал (назва)",
        "Од. виміру",
        "Кількість",
        "Локація",
        "Замовлення/робота",
    ])

    for r in rows:
        local_dt = localtime_filter(r["created_at"])
        writer.writerow([
            r["id"],
            local_dt,
            r["direction"],
            r["worker_name"] or "",
            r["material_code"],
            r["material_name"],
            r["material_unit"],
            r["qty"],
            r["location_name"],
            r["job"] or "",
        ])

    csv_data = output.getvalue()
    output.close()

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=container_history.csv"
        },
    )


# ----------------- QR-коди -----------------


@app.route("/admin/containers/print_qr")
@login_required
def print_qr():
    location_id = request.args.get("location_id") or None
    size = request.args.get("size", "medium")

    locations = get_locations()
    containers = None
    selected_location_id = int(location_id) if location_id else None

    if location_id:
        containers = get_containers_with_stock(location_id, None)

    return render_template(
        "admin_print_qr.html",
        locations=locations,
        containers=containers,
        selected_location_id=selected_location_id,
        size=size,
    )


@app.route("/admin/container/<int:container_id>/qr.png")
@login_required
def container_qr(container_id):
    db = get_db()
    container = db.execute(
        "SELECT qr_token FROM containers WHERE id = ?;",
        (container_id,),
    ).fetchone()

    if container is None:
        abort(404)

    use_url = url_for("use_material", token=container["qr_token"], _external=True)

    img = qrcode.make(use_url)
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")


# ----------------- Списання по QR (для працівників) -----------------


@app.route("/use/<token>", methods=["GET", "POST"])
def use_material(token):
    db = get_db()

    container = db.execute(
        """
        SELECT
            c.id AS container_id,
            c.min_balance,
            m.code AS material_code,
            m.name AS material_name,
            m.unit AS material_unit,
            l.name AS location_name,
            COALESCE(SUM(
                CASE
                    WHEN t.direction = 'IN' THEN t.qty
                    WHEN t.direction = 'OUT' THEN -t.qty
                END
            ), 0) AS balance
        FROM containers c
        JOIN materials m ON c.material_id = m.id
        JOIN locations l ON c.location_id = l.id
        LEFT JOIN transactions t ON t.container_id = c.id
        WHERE c.qr_token = ?
        GROUP BY c.id, c.min_balance, m.code, m.name, m.unit, l.name;
        """,
        (token,),
    ).fetchone()

    if container is None:
        return "Невірний або застарілий QR-код.", 404

    # Чи є залогінений працівник (не адмін)?
    current_worker = None
    if session.get("worker_id"):
        current_worker = db.execute(
            "SELECT * FROM workers WHERE id = ?;",
            (session["worker_id"],),
        ).fetchone()

    workers = get_workers()

    if request.method == "POST":
        # Якщо є залогінений працівник – використовуємо його, ігноруємо форму вибору
        if current_worker:
            worker_id = current_worker["id"]
        else:
            worker_id = request.form.get("worker_id") or None
            pin = request.form.get("pin", "").strip()

            if pin:
                row = db.execute(
                    "SELECT id FROM workers WHERE pin = ?;",
                    (pin,),
                ).fetchone()
                if row is None:
                    flash("Невірний PIN працівника.", "error")
                    return redirect(url_for("use_material", token=token))
                worker_id = row["id"]

            if not worker_id:
                flash("Оберіть працівника або введіть PIN.", "error")
                return redirect(url_for("use_material", token=token))

        qty_str = request.form.get("qty", "").strip()
        job = request.form.get("job", "").strip()

        try:
            qty = float(qty_str.replace(",", "."))
        except ValueError:
            flash("Кількість має бути числом.", "error")
            return redirect(url_for("use_material", token=token))

        if qty <= 0:
            flash("Кількість має бути більшою за 0.", "error")
            return redirect(url_for("use_material", token=token))

        current_balance = container["balance"] or 0
        if qty > current_balance:
            flash(
                f"Неможливо списати {qty} {container['material_unit']}: "
                f"у ємності лише {current_balance} {container['material_unit']}.",
                "error",
            )
            return redirect(url_for("use_material", token=token))

        now = datetime.utcnow().isoformat()

        db.execute(
            """
            INSERT INTO transactions (created_at, worker_id, container_id, qty, direction, job)
            VALUES (?, ?, ?, ?, 'OUT', ?);
            """,
            (now, worker_id, container["container_id"], qty, job or None),
        )
        db.commit()

        logger.info(
            f"OUT: worker_id={worker_id}, container_id={container['container_id']}, qty={qty}"
        )
        flash("Списання збережено. Дякуємо!", "success")
        return redirect(url_for("use_material", token=token))

    return render_template(
        "use_material.html",
        container=container,
        workers=workers,
        current_worker=current_worker,
    )


# ----------------- Прихід матеріалу (розподіл по ємностях) -----------------


@app.route("/admin/material_in", methods=["GET", "POST"])
@login_required
def admin_material_in():
    db = get_db()
    materials = get_materials()

    if request.method == "POST":
        material_id = request.form.get("material_id")
        if not material_id:
            flash("Оберіть матеріал.", "error")
            return redirect(url_for("admin_material_in"))

        material = db.execute(
            "SELECT * FROM materials WHERE id = ?;",
            (material_id,),
        ).fetchone()
        if material is None:
            flash("Матеріал не знайдено.", "error")
            return redirect(url_for("admin_material_in"))

        job = request.form.get("job", "").strip()

        containers = db.execute(
            """
            SELECT c.id
            FROM containers c
            WHERE c.material_id = ?
            ORDER BY c.id;
            """,
            (material_id,),
        ).fetchall()

        if not containers:
            flash("Для цього матеріалу немає жодної ємності.", "error")
            return redirect(url_for("admin_material_in", material_id=material_id))

        now = datetime.utcnow().isoformat()
        total_in = 0.0
        any_added = False

        for c in containers:
            field = f"qty_{c['id']}"
            qty_str = request.form.get(field, "").strip()
            if not qty_str:
                continue
            try:
                qty = float(qty_str.replace(",", "."))
            except ValueError:
                flash("Кількість має бути числом.", "error")
                return redirect(url_for("admin_material_in", material_id=material_id))

            if qty <= 0:
                continue

            any_added = True
            total_in += qty

            db.execute(
                """
                INSERT INTO transactions (created_at, worker_id, container_id, qty, direction, job)
                VALUES (?, NULL, ?, ?, 'IN', ?);
                """,
                (now, c["id"], qty, job or None),
            )

        if not any_added:
            flash("Не введено жодної кількості для розподілу.", "error")
            return redirect(url_for("admin_material_in", material_id=material_id))

        db.commit()
        flash(
            f"Прихід матеріалу {material['code']} – {material['name']} "
            f"розподілено по ємностях. Всього: {total_in} {material['unit']}.",
            "success",
        )
        return redirect(url_for("admin_material_in", material_id=material_id))

    # GET
    material_id = request.args.get("material_id")
    selected_material = None
    containers = []
    material_balance = None

    if material_id:
        selected_material = db.execute(
            "SELECT * FROM materials WHERE id = ?;",
            (material_id,),
        ).fetchone()
        if selected_material:
            containers = db.execute(
                """
                SELECT
                    c.id,
                    l.name AS location_name,
                    COALESCE(SUM(
                        CASE
                            WHEN t.direction='IN' THEN t.qty
                            WHEN t.direction='OUT' THEN -t.qty
                        END
                    ),0) AS balance
                FROM containers c
                JOIN locations l ON c.location_id = l.id
                LEFT JOIN transactions t ON t.container_id = c.id
                WHERE c.material_id = ?
                GROUP BY c.id, l.name
                ORDER BY l.name, c.id;
                """,
                (material_id,),
            ).fetchall()

            material_balance = db.execute(
                """
                SELECT
                    COALESCE(SUM(
                        CASE
                            WHEN t.direction='IN' THEN t.qty
                            WHEN t.direction='OUT' THEN -t.qty
                        END
                    ),0) AS balance
                FROM containers c
                LEFT JOIN transactions t ON t.container_id = c.id
                WHERE c.material_id = ?;
                """,
                (material_id,),
            ).fetchone()

    return render_template(
        "admin_material_in.html",
        materials=materials,
        selected_material=selected_material,
        containers=containers,
        material_balance=material_balance,
    )


# ----------------- Прихід напряму в ємності (старий режим) -----------------


@app.route("/admin/stock", methods=["GET", "POST"])
@login_required
def admin_stock():
    db = get_db()

    if request.method == "POST":
        container_id = request.form.get("container_id")
        qty_str = request.form.get("qty", "").strip()
        job = request.form.get("job", "").strip()

        if not container_id or not qty_str:
            flash("Оберіть ємність і введіть кількість.", "error")
            return redirect(url_for("admin_stock"))

        try:
            qty = float(qty_str.replace(",", "."))
        except ValueError:
            flash("Кількість має бути числом.", "error")
            return redirect(url_for("admin_stock"))

        if qty <= 0:
            flash("Кількість має бути більшою за 0.", "error")
            return redirect(url_for("admin_stock"))

        now = datetime.utcnow().isoformat()

        db.execute(
            """
            INSERT INTO transactions (created_at, worker_id, container_id, qty, direction, job)
            VALUES (?, NULL, ?, ?, 'IN', ?);
            """,
            (now, container_id, qty, job or None),
        )
        db.commit()

        logger.info(f"IN: container_id={container_id}, qty={qty}")
        flash("Прихід збережено.", "success")
        return redirect(url_for("admin_stock"))

    containers = get_containers_with_stock()
    return render_template("admin_stock.html", containers=containers)


# ----------------- Залишки по матеріалах -----------------


@app.route("/admin/summary")
@login_required
def admin_summary():
    materials = get_materials_stock()
    return render_template("admin_summary.html", materials=materials)


# ----------------- Звіти -----------------


@app.route("/admin/report/workers")
@login_required
def report_workers():
    db = get_db()
    date_from = request.args.get("date_from") or None
    date_to = request.args.get("date_to") or None
    material_id = request.args.get("material_id") or None

    conditions = ["t.direction = 'OUT'"]
    params = []

    if date_from:
        conditions.append("t.created_at >= ?")
        params.append(date_from + "T00:00:00")

    if date_to:
        conditions.append("t.created_at <= ?")
        params.append(date_to + "T23:59:59")

    if material_id:
        conditions.append("m.id = ?")
        params.append(material_id)

    where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""

    query = f"""
        SELECT
            w.id AS worker_id,
            w.name AS worker_name,
            m.code AS material_code,
            m.name AS material_name,
            m.unit AS material_unit,
            SUM(t.qty) AS total_qty
        FROM transactions t
        JOIN workers w ON t.worker_id = w.id
        JOIN containers c ON t.container_id = c.id
        JOIN materials m ON c.material_id = m.id
        {where_clause}
        GROUP BY
            w.id, w.name,
            m.id, m.code, m.name, m.unit
        ORDER BY w.name, m.code;
    """
    rows = db.execute(query, params).fetchall()
    materials = get_materials()

    selected_material_id = int(material_id) if material_id else None

    filters = {
        "date_from": date_from,
        "date_to": date_to,
        "material_id": material_id,
    }

    return render_template(
        "admin_report_workers.html",
        rows=rows,
        materials=materials,
        filters=filters,
        selected_material_id=selected_material_id,
    )


@app.route("/admin/report/materials")
@login_required
def report_materials():
    db = get_db()
    date_from = request.args.get("date_from") or None
    date_to = request.args.get("date_to") or None
    worker_id = request.args.get("worker_id") or None

    conditions = ["t.direction = 'OUT'"]
    params = []

    if date_from:
        conditions.append("t.created_at >= ?")
        params.append(date_from + "T00:00:00")

    if date_to:
        conditions.append("t.created_at <= ?")
        params.append(date_to + "T23:59:59")

    if worker_id:
        conditions.append("w.id = ?")
        params.append(worker_id)

    where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""

    query = f"""
        SELECT
            m.id AS material_id,
            m.code AS material_code,
            m.name AS material_name,
            m.unit AS material_unit,
            SUM(t.qty) AS total_qty
        FROM transactions t
        JOIN containers c ON t.container_id = c.id
        JOIN materials m ON c.material_id = m.id
        LEFT JOIN workers w ON t.worker_id = w.id
        {where_clause}
        GROUP BY m.id, m.code, m.name, m.unit
        ORDER BY m.code;
    """
    rows = db.execute(query, params).fetchall()
    workers = get_workers()

    selected_worker_id = int(worker_id) if worker_id else None

    filters = {
        "date_from": date_from,
        "date_to": date_to,
        "worker_id": worker_id,
    }

    return render_template(
        "admin_report_materials.html",
        rows=rows,
        workers=workers,
        filters=filters,
        selected_worker_id=selected_worker_id,
    )


# ----------------- Журнал операцій -----------------


def _build_transactions_query(filters, limit=None, offset=None):
    conditions = []
    params = []

    if filters.get("worker_id"):
        conditions.append("t.worker_id = ?")
        params.append(filters["worker_id"])

    if filters.get("material_id"):
        conditions.append("m.id = ?")
        params.append(filters["material_id"])

    if filters.get("direction") in ("IN", "OUT"):
        conditions.append("t.direction = ?")
        params.append(filters["direction"])

    if filters.get("date_from"):
        conditions.append("t.created_at >= ?")
        params.append(filters["date_from"] + "T00:00:00")

    if filters.get("date_to"):
        conditions.append("t.created_at <= ?")
        params.append(filters["date_to"] + "T23:59:59")

    q = filters.get("q")
    if q:
        pattern = f"%{q}%"
        conditions.append(
            """
            (
                t.job LIKE ?
                OR m.name LIKE ?
                OR m.code LIKE ?
                OR COALESCE(w.name, '') LIKE ?
                OR l.name LIKE ?
            )
            """
        )
        params.extend([pattern] * 5)

    if filters.get("storno_only"):
        conditions.append("t.job LIKE ?")
        params.append("%сторно%")

    where_clause = ""
    if conditions:
        where_clause = "WHERE " + " AND ".join(conditions)

    query = f"""
        SELECT
            t.id,
            t.created_at,
            t.qty,
            t.direction,
            t.job,
            w.name AS worker_name,
            m.code AS material_code,
            m.name AS material_name,
            m.unit AS material_unit,
            l.name AS location_name
        FROM transactions t
        JOIN containers c ON t.container_id = c.id
        JOIN materials m ON c.material_id = m.id
        JOIN locations l ON c.location_id = l.id
        LEFT JOIN workers w ON t.worker_id = w.id
        {where_clause}
        ORDER BY t.created_at DESC
    """

    if limit is not None:
        query += " LIMIT ?"
        params.append(limit)
        if offset is not None:
            query += " OFFSET ?"
            params.append(offset)

    return query, params


@app.route("/admin/transactions")
@login_required
def admin_transactions():
    db = get_db()

    page = request.args.get("page", 1, type=int)
    per_page = 100
    offset = (page - 1) * per_page

    filters = {
        "worker_id": request.args.get("worker_id") or None,
        "material_id": request.args.get("material_id") or None,
        "direction": request.args.get("direction") or None,
        "date_from": request.args.get("date_from") or None,
        "date_to": request.args.get("date_to") or None,
        "q": request.args.get("q") or None,
        "storno_only": True if request.args.get("storno") == "1" else False,
    }

    query, params = _build_transactions_query(filters, limit=per_page, offset=offset)
    transactions = db.execute(query, params).fetchall()

    has_next = len(transactions) == per_page

    workers = get_workers()
    materials = get_materials()

    selected_worker_id = request.args.get("worker_id", type=int)
    selected_material_id = request.args.get("material_id", type=int)

    return render_template(
        "admin_transactions.html",
        transactions=transactions,
        workers=workers,
        materials=materials,
        filters=filters,
        selected_worker_id=selected_worker_id,
        selected_material_id=selected_material_id,
        page=page,
        has_next=has_next,
    )


@app.route("/admin/transactions/<int:tx_id>/reverse", methods=["POST"])
@login_required
def reverse_transaction(tx_id):
    db = get_db()
    tx = db.execute(
        "SELECT * FROM transactions WHERE id = ?;",
        (tx_id,),
    ).fetchone()

    if tx is None:
        flash("Операцію не знайдено.", "error")
        return redirect(url_for("admin_transactions"))

    opposite_dir = "IN" if tx["direction"] == "OUT" else "OUT"
    now = datetime.utcnow().isoformat()
    base_job = tx["job"] or ""
    job = (base_job + " ").strip() + f"(сторно операції #{tx_id})"

    cur = db.execute(
        """
        INSERT INTO transactions (created_at, worker_id, container_id, qty, direction, job)
        VALUES (?, ?, ?, ?, ?, ?);
        """,
        (now, tx["worker_id"], tx["container_id"], tx["qty"], opposite_dir, job),
    )
    db.commit()

    logger.info(f"Reverse transaction #{tx_id} -> new #{cur.lastrowid}")
    flash(f"Створено сторно операції #{tx_id}.", "success")
    return redirect(url_for("admin_transactions"))


@app.route("/admin/transactions/export")
@login_required
def export_transactions_csv():
    db = get_db()

    filters = {
        "worker_id": request.args.get("worker_id") or None,
        "material_id": request.args.get("material_id") or None,
        "direction": request.args.get("direction") or None,
        "date_from": request.args.get("date_from") or None,
        "date_to": request.args.get("date_to") or None,
        "q": request.args.get("q") or None,
        "storno_only": True if request.args.get("storno") == "1" else False,
    }

    query, params = _build_transactions_query(filters)
    rows = db.execute(query, params).fetchall()

    output = StringIO()
    writer = csv.writer(output, delimiter=";")

    writer.writerow([
        "ID",
        "Дата/час (локальний)",
        "Тип (IN/OUT)",
        "Працівник",
        "Матеріал (код)",
        "Матеріал (назва)",
        "Од. виміру",
        "Кількість",
        "Локація",
        "Замовлення/робота",
    ])

    for r in rows:
        local_dt = localtime_filter(r["created_at"])
        writer.writerow([
            r["id"],
            local_dt,
            r["direction"],
            r["worker_name"] or "",
            r["material_code"],
            r["material_name"],
            r["material_unit"],
            r["qty"],
            r["location_name"],
            r["job"] or "",
        ])

    csv_data = output.getvalue()
    output.close()

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=transactions.csv"
        },
    )


# ----------------- Глобальний пошук -----------------


@app.route("/admin/search")
@login_required
def admin_search():
    db = get_db()
    q = request.args.get("q", "").strip()

    materials = []
    locations = []
    containers = []

    if q:
        pattern = f"%{q}%"
        materials = db.execute(
            """
            SELECT * FROM materials
            WHERE code LIKE ? OR name LIKE ?
            ORDER BY code;
            """,
            (pattern, pattern),
        ).fetchall()

        locations = db.execute(
            """
            SELECT * FROM locations
            WHERE name LIKE ?
            ORDER BY name;
            """,
            (pattern,),
        ).fetchall()

        containers = get_containers_with_stock(search=q)

    return render_template(
        "admin_search.html",
        q=q,
        materials=materials,
        locations=locations,
        containers=containers,
    )


# ----------------- Запуск -----------------


if __name__ == "__main__":
    import os  # якщо вже є на початку файлу – вдруге додавати НЕ треба
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port, debug=True)
