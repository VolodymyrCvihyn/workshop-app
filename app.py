import os
import sqlite3
import logging
import csv
import secrets
from io import BytesIO, StringIO
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Flask,
    g,
    session,
    redirect,
    url_for,
    render_template,
    flash,
    send_file,
    request,
    abort,
    Response,
)
from werkzeug.security import generate_password_hash, check_password_hash
from zoneinfo import ZoneInfo
import qrcode
from openpyxl import Workbook

# ----------------- Налаштування -----------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "workshop.db"))

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

LOCAL_TZ = ZoneInfo(os.environ.get("APP_TIMEZONE", "Europe/Kyiv"))


# ----------------- Допоміжні функції -----------------


def _format_bytes(num: int) -> str:
    if num is None:
        return "невідомо"
    n = float(num)
    for unit in ["Б", "КБ", "МБ", "ГБ", "ТБ"]:
        if n < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} ПБ"


def localtime_filter(value: str) -> str:
    if not value:
        return ""
    try:
        dt = datetime.fromisoformat(value)
    except Exception:
        return value
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt_local = dt.astimezone(LOCAL_TZ)
    return dt_local.strftime("%Y-%m-%d %H:%M:%S")


app.jinja_env.filters["localtime"] = localtime_filter


def get_db():
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA foreign_keys = ON;")
        except sqlite3.OperationalError:
            logger.warning("Не вдалося встановити WAL-режим або foreign_keys для SQLite")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Створення таблиць та базова ініціалізація (ідемпотентно)."""
    if os.path.dirname(DB_PATH):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Матеріали
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS materials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            unit TEXT NOT NULL
        );
        """
    )

    # Локації (шафи)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS locations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
        );
        """
    )

    # Працівники
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS workers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            pin TEXT
        );
        """
    )

    # Ємності
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS containers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            material_id INTEGER NOT NULL,
            location_id INTEGER NOT NULL,
            qr_token TEXT,
            min_balance REAL,
            FOREIGN KEY(material_id) REFERENCES materials(id),
            FOREIGN KEY(location_id) REFERENCES locations(id)
        );
        """
    )

    # Операції
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            worker_id INTEGER,
            container_id INTEGER NOT NULL,
            qty REAL NOT NULL,
            direction TEXT NOT NULL CHECK(direction IN ('IN','OUT')),
            job TEXT,
            is_service INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(worker_id) REFERENCES workers(id),
            FOREIGN KEY(container_id) REFERENCES containers(id)
        );
        """
    )

    # Архів операцій
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS transactions_archive (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            worker_id INTEGER,
            container_id INTEGER NOT NULL,
            qty REAL NOT NULL,
            direction TEXT NOT NULL CHECK(direction IN ('IN','OUT')),
            job TEXT,
            is_service INTEGER NOT NULL DEFAULT 0
        );
        """
    )

    # Користувачі
    cur.execute(
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

    # Міграції існуючих БД
    def col_exists(table: str, col: str) -> bool:
        info = cur.execute(f"PRAGMA table_info({table});").fetchall()
        return any(row[1] == col for row in info)

    if not col_exists("containers", "min_balance"):
        logger.info("ALTER TABLE containers ADD COLUMN min_balance REAL;")
        cur.execute("ALTER TABLE containers ADD COLUMN min_balance REAL;")

    if not col_exists("containers", "qr_token"):
        logger.info("ALTER TABLE containers ADD COLUMN qr_token TEXT;")
        cur.execute("ALTER TABLE containers ADD COLUMN qr_token TEXT;")

    if not col_exists("workers", "pin"):
        logger.info("ALTER TABLE workers ADD COLUMN pin TEXT;")
        cur.execute("ALTER TABLE workers ADD COLUMN pin TEXT;")

    if not col_exists("transactions", "is_service"):
        logger.info("ALTER TABLE transactions ADD COLUMN is_service INTEGER NOT NULL DEFAULT 0;")
        cur.execute("ALTER TABLE transactions ADD COLUMN is_service INTEGER NOT NULL DEFAULT 0;")

    conn.commit()

    # Заповнити відсутні qr_token для ємностей
    rows = cur.execute("SELECT id, qr_token FROM containers;").fetchall()
    updated = 0
    for r in rows:
        if not r["qr_token"]:
            token = secrets.token_urlsafe(16)
            cur.execute(
                "UPDATE containers SET qr_token = ? WHERE id = ?;",
                (token, r["id"]),
            )
            updated += 1
    if updated:
        logger.info("Додано qr_token для %s ємностей", updated)

    # Переконатися, що є хоч один адмін
    row = cur.execute("SELECT id FROM users WHERE is_admin = 1 LIMIT 1;").fetchone()
    if row is None:
        pwd = os.environ.get("ADMIN_PASSWORD", "admin")
        cur.execute(
            "INSERT INTO users (username, password_hash, is_admin, worker_id) VALUES (?, ?, 1, NULL);",
            ("admin", generate_password_hash(pwd)),
        )
        logger.warning("Створено адміністратора admin / %s. Не забудьте змінити пароль.", pwd)

    conn.commit()
    conn.close()


# Ініціалізація БД при старті модуля
init_db()


# ----------------- Глобальний контекст (тема) -----------------


@app.context_processor
def inject_theme():
    return {"theme": session.get("theme", "light")}


# ----------------- Декоратори -----------------


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id") or not session.get("is_admin"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


# ----------------- Службові функції доступу до даних -----------------


def get_materials():
    db = get_db()
    return db.execute(
        "SELECT * FROM materials ORDER BY CAST(code AS INTEGER) ASC, code ASC;"
    ).fetchall()


def get_locations():
    db = get_db()
    return db.execute(
        "SELECT * FROM locations ORDER BY name;"
    ).fetchall()


def get_workers():
    db = get_db()
    return db.execute(
        "SELECT * FROM workers ORDER BY name;"
    ).fetchall()


def get_containers_with_stock(location_id=None, search=None, material_id=None):
    db = get_db()
    conditions = []
    params = []

    if location_id:
        conditions.append("c.location_id = ?")
        params.append(location_id)

    if material_id:
        conditions.append("c.material_id = ?")
        params.append(material_id)

    if search:
        pattern = f"%{search}%"
        conditions.append(
            "(m.code LIKE ? OR m.name LIKE ? OR l.name LIKE ? OR CAST(c.id AS TEXT) LIKE ?)"
        )
        params.extend([pattern, pattern, pattern, pattern])

    where_clause = ""
    if conditions:
        where_clause = "WHERE " + " AND ".join(conditions)

    query = f"""
        SELECT
            c.id,
            c.material_id,
            c.location_id,
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
            c.material_id,
            c.location_id,
            c.min_balance,
            m.code,
            m.name,
            m.unit,
            l.name
        ORDER BY l.name, m.code, c.id;
    """
    return db.execute(query, params).fetchall()


def get_materials_stock():
    db = get_db()
    query = """
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
        ORDER BY CAST(m.code AS INTEGER) ASC, m.code ASC;
    """
    return db.execute(query).fetchall()


# ----------------- Аутентифікація -----------------


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        db = get_db()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = db.execute(
            "SELECT * FROM users WHERE username = ?;",
            (username,),
        ).fetchone()

        if not user or not check_password_hash(user["password_hash"], password):
            flash("Невірний логін або пароль.", "error")
            return render_template("login.html")

        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["is_admin"] = bool(user["is_admin"])
        if user["worker_id"]:
            session["worker_id"] = user["worker_id"]

        next_url = request.args.get("next")
        if session["is_admin"]:
            return redirect(next_url or url_for("admin_index"))
        else:
            return redirect(next_url or url_for("index"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Вихід виконано.", "info")
    return redirect(url_for("index"))


@app.route("/toggle-theme")
def toggle_theme():
    current = session.get("theme", "light")
    session["theme"] = "dark" if current == "light" else "light"
    next_url = request.args.get("next") or request.referrer or url_for("index")
    return redirect(next_url)


# ----------------- Загальні сторінки -----------------


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/admin")
@login_required
def admin_index():
    locations = get_locations()
    all_containers = get_containers_with_stock()

    shelves = []
    by_loc = {}
    for c in all_containers:
        by_loc.setdefault(c["location_id"], []).append(c)

    for loc in locations:
        containers = by_loc.get(loc["id"], [])
        has_low = any(
            (row["min_balance"] is not None) and (row["balance"] < row["min_balance"])
            for row in containers
        )
        shelves.append(
            {
                "location": loc,
                "containers": containers,
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

    filename = os.path.basename(DB_PATH)
    return send_file(DB_PATH, as_attachment=True, download_name=filename)


# ----------------- Обліковий запис адміністратора -----------------


@app.route("/admin/account", methods=["GET", "POST"])
@login_required
def admin_account():
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE id = ?;",
        (session["user_id"],),
    ).fetchone()
    if user is None:
        abort(403)

    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        new_password2 = request.form.get("new_password2", "")

        if not check_password_hash(user["password_hash"], current_password):
            flash("Поточний пароль невірний.", "error")
            return render_template("admin_account.html", user=user)

        if not new_password:
            flash("Новий пароль не може бути порожнім.", "error")
            return render_template("admin_account.html", user=user)

        if new_password != new_password2:
            flash("Паролі не співпадають.", "error")
            return render_template("admin_account.html", user=user)

        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?;",
            (generate_password_hash(new_password), user["id"]),
        )
        db.commit()
        flash("Пароль змінено.", "success")
        return redirect(url_for("admin_account"))

    return render_template("admin_account.html", user=user)


# ----------------- Матеріали -----------------


@app.route("/admin/materials", methods=["GET", "POST"])
@login_required
def admin_materials():
    db = get_db()

    if request.method == "POST":
        action = request.form.get("action")
        if action == "add":
            name = request.form.get("name", "").strip()
            unit = request.form.get("unit", "").strip()
            if not name or not unit:
                flash("Назва та одиниця виміру обовʼязкові.", "error")
            else:
                row = db.execute(
                    "SELECT MAX(CAST(code AS INTEGER)) AS max_code FROM materials WHERE code GLOB '[0-9]*';"
                ).fetchone()
                max_code = row["max_code"]
                next_code = 1 if max_code is None else int(max_code) + 1
                code = str(next_code)
                try:
                    db.execute(
                        "INSERT INTO materials (code, name, unit) VALUES (?, ?, ?);",
                        (code, name, unit),
                    )
                    db.commit()
                    flash(f"Матеріал додано з кодом {code}.", "success")
                except sqlite3.IntegrityError:
                    flash("Не вдалося додати матеріал (можливий дублікат).", "error")

        elif action == "edit":
            material_id = request.form.get("material_id")
            name = request.form.get("name", "").strip()
            unit = request.form.get("unit", "").strip()
            if not material_id or not name or not unit:
                flash("Необхідно вказати матеріал, назву та одиницю.", "error")
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

    db.execute(
        """
        DELETE FROM transactions
        WHERE container_id IN (
            SELECT id FROM containers WHERE material_id = ?
        );
        """,
        (material_id,),
    )
    db.execute("DELETE FROM containers WHERE material_id = ?;", (material_id,))
    db.execute("DELETE FROM materials WHERE id = ?;", (material_id,))
    db.commit()

    logger.info("Deleted material id=%s and related containers/transactions", material_id)
    flash("Матеріал та всі його ємності й операції видалено.", "success")
    return redirect(url_for("admin_materials"))


@app.route("/admin/materials/<int:material_id>/containers")
@login_required
def goto_material_containers(material_id):
    return redirect(url_for("admin_containers", material_id=material_id))


# ----------------- Локації -----------------


@app.route("/admin/locations", methods=["GET", "POST"])
@login_required
def admin_locations():
    db = get_db()

    if request.method == "POST":
        action = request.form.get("action")
        if action == "add":
            name = request.form.get("name", "").strip()
            if not name:
                flash("Назва локації обовʼязкова.", "error")
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
                flash("Необхідно вказати локацію та назву.", "error")
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

    db.execute(
        """
        DELETE FROM transactions
        WHERE container_id IN (
            SELECT id FROM containers WHERE location_id = ?
        );
        """,
        (location_id,),
    )
    db.execute("DELETE FROM containers WHERE location_id = ?;", (location_id,))
    db.execute("DELETE FROM locations WHERE id = ?;", (location_id,))
    db.commit()

    logger.info("Deleted location id=%s and related containers/transactions", location_id)
    flash("Локацію та всі її ємності й операції видалено.", "success")
    return redirect(url_for("admin_locations"))


# ----------------- Працівники -----------------


@app.route("/admin/workers", methods=["GET", "POST"])
@login_required
def admin_workers():
    db = get_db()

    if request.method == "POST":
        action = request.form.get("action")
        if action == "add":
            name = request.form.get("name", "").strip()
            pin = request.form.get("pin", "").strip() or None
            if not name:
                flash("Імʼя працівника обовʼязкове.", "error")
            else:
                try:
                    db.execute(
                        "INSERT INTO workers (name, pin) VALUES (?, ?);",
                        (name, pin),
                    )
                    db.commit()
                    flash("Працівника додано.", "success")
                except sqlite3.IntegrityError:
                    flash("Помилка додавання. Перевірте унікальність PIN.", "error")

        elif action == "edit_name":
            worker_id = request.form.get("worker_id")
            name = request.form.get("name", "").strip()
            if not worker_id or not name:
                flash("Необхідно вказати працівника та імʼя.", "error")
            else:
                db.execute(
                    "UPDATE workers SET name = ? WHERE id = ?;",
                    (name, worker_id),
                )
                db.commit()
                flash("Імʼя працівника оновлено.", "success")

        elif action == "update_pin":
            worker_id = request.form.get("worker_id")
            pin = request.form.get("pin", "").strip() or None
            if not worker_id:
                flash("Необхідно вказати працівника.", "error")
            else:
                try:
                    db.execute(
                        "UPDATE workers SET pin = ? WHERE id = ?;",
                        (pin, worker_id),
                    )
                    db.commit()
                    flash("PIN оновлено.", "success")
                except sqlite3.IntegrityError:
                    flash("Такий PIN вже використовується іншим працівником.", "error")

        elif action == "create_user":
            worker_id = request.form.get("worker_id")
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            if not worker_id or not username or not password:
                flash("Необхідно вказати працівника, логін і пароль.", "error")
            else:
                row = db.execute(
                    "SELECT id FROM users WHERE worker_id = ? AND is_admin = 0;",
                    (worker_id,),
                ).fetchone()
                if row:
                    flash("Для цього працівника вже існує обліковий запис.", "error")
                else:
                    try:
                        db.execute(
                            "INSERT INTO users (username, password_hash, is_admin, worker_id) VALUES (?, ?, 0, ?);",
                            (username, generate_password_hash(password), worker_id),
                        )
                        db.commit()
                        flash("Обліковий запис створено.", "success")
                    except sqlite3.IntegrityError:
                        flash("Такий логін вже існує.", "error")

        elif action == "change_user_password":
            worker_id = request.form.get("worker_id")
            password = request.form.get("password", "")
            if not worker_id or not password:
                flash("Потрібно вказати працівника і новий пароль.", "error")
            else:
                row = db.execute(
                    "SELECT id FROM users WHERE worker_id = ? AND is_admin = 0;",
                    (worker_id,),
                ).fetchone()
                if not row:
                    flash("Для цього працівника немає облікового запису.", "error")
                else:
                    db.execute(
                        "UPDATE users SET password_hash = ? WHERE id = ?;",
                        (generate_password_hash(password), row["id"]),
                    )
                    db.commit()
                    flash("Пароль змінено.", "success")

        return redirect(url_for("admin_workers"))

    workers = get_db().execute(
        """
        SELECT
            w.id,
            w.name,
            w.pin,
            u.username
        FROM workers w
        LEFT JOIN users u ON u.worker_id = w.id AND u.is_admin = 0
        ORDER BY w.name;
        """
    ).fetchall()

    return render_template("admin_workers.html", workers=workers)


@app.route("/admin/workers/<int:worker_id>/delete", methods=["POST"])
@login_required
def delete_worker(worker_id):
    db = get_db()

    db.execute(
        "UPDATE transactions SET worker_id = NULL WHERE worker_id = ?;",
        (worker_id,),
    )
    db.execute(
        "DELETE FROM users WHERE worker_id = ? AND is_admin = 0;",
        (worker_id,),
    )
    db.execute("DELETE FROM workers WHERE id = ?;", (worker_id,))
    db.commit()

    logger.info("Deleted worker id=%s and detached related users/transactions", worker_id)
    flash("Працівника видалено. Операції залишилися без привʼязки до нього.", "success")
    return redirect(url_for("admin_workers"))


@app.route("/admin/workers/<int:worker_id>/transactions")
@login_required
def goto_worker_transactions(worker_id):
    return redirect(url_for("admin_transactions", worker_id=worker_id))


# ----------------- Залишки та звіти -----------------


@app.route("/admin/summary")
@login_required
def admin_summary():
    materials = get_materials_stock()
    return render_template("admin_summary.html", materials=materials)


@app.route("/admin/summary/export")
@login_required
def export_summary_excel():
    materials = get_materials_stock()

    wb = Workbook()
    ws = wb.active
    ws.title = "Залишки"

    ws.append(["Код", "Назва", "Залишок", "Од. виміру"])

    for m in materials:
        balance = m["balance"] if m["balance"] is not None else 0
        ws.append(
            [
                m["code"],
                m["name"],
                float(balance),
                m["unit"],
            ]
        )

    buf = BytesIO()
    wb.save(buf)
    buf.seek(0)

    return send_file(
        buf,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        as_attachment=True,
        download_name="materials_summary.xlsx",
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


# ----------------- Стан системи -----------------


@app.route("/admin/system", methods=["GET", "POST"])
@login_required
def admin_system():
    db = get_db()
    integrity_result = None

    if request.method == "POST":
        action = request.form.get("action")
        if action == "integrity":
            row = db.execute("PRAGMA integrity_check;").fetchone()
            integrity_result = row[0] if row else "невідомо"
            flash(f"Результат перевірки цілісності: {integrity_result}", "info")
        elif action == "vacuum":
            db.execute("VACUUM;")
            db.commit()
            flash("VACUUM виконано. База оптимізована.", "success")
        elif action == "archive":
            archive_before = request.form.get("archive_before", "").strip()
            if not archive_before:
                flash("Вкажіть дату для архівації.", "error")
            else:
                cutoff = archive_before + "T00:00:00"
                row = db.execute(
                    "SELECT COUNT(*) AS cnt FROM transactions WHERE created_at < ?;",
                    (cutoff,),
                ).fetchone()
                to_archive = row["cnt"]
                if to_archive == 0:
                    flash("Немає операцій, старіших за вказану дату.", "info")
                else:
                    db.execute(
                        """
                        INSERT INTO transactions_archive (
                            created_at, worker_id, container_id, qty, direction, job, is_service
                        )
                        SELECT created_at, worker_id, container_id, qty, direction, job, is_service
                        FROM transactions
                        WHERE created_at < ?;
                        """,
                        (cutoff,),
                    )
                    db.execute(
                        "DELETE FROM transactions WHERE created_at < ?;",
                        (cutoff,),
                    )
                    db.commit()
                    flash(f"В архів перенесено {to_archive} операцій.", "success")

    stats = {}
    if os.path.exists(DB_PATH):
        stats["db_path"] = DB_PATH
        stats["db_size"] = os.path.getsize(DB_PATH)
    else:
        stats["db_path"] = DB_PATH
        stats["db_size"] = None

    tables = [
        "materials",
        "locations",
        "workers",
        "containers",
        "transactions",
        "transactions_archive",
        "users",
    ]
    counts = {}
    for t in tables:
        try:
            row = db.execute(f"SELECT COUNT(*) AS cnt FROM {t};").fetchone()
            counts[t] = row["cnt"]
        except sqlite3.OperationalError:
            counts[t] = "—"
    stats["counts"] = counts

    if os.path.exists(DB_PATH):
        stats["db_size"] = os.path.getsize(DB_PATH)

    stats["db_size_human"] = _format_bytes(stats["db_size"]) if stats["db_size"] is not None else "невідомо"

    return render_template("admin_system.html", stats=stats, integrity_result=integrity_result)


# ----------------- Ємності та операції -----------------
@app.route("/admin/containers", methods=["GET", "POST"])
@login_required
def admin_containers():
    db = get_db()
    locations = get_locations()
    materials = get_materials()

    selected_location_id = request.args.get("location_id", type=int)
    selected_material_id = request.args.get("material_id", type=int)
    search_q = request.args.get("q", "").strip() or None

    if request.method == "POST":
        action = request.form.get("action")
        if action == "add":
            material_id = request.form.get("material_id")
            location_id = request.form.get("location_id")
            min_balance_raw = request.form.get("min_balance", "").strip()

            if not material_id or not location_id:
                flash("Необхідно обрати матеріал і локацію.", "error")
            else:
                min_balance = None
                if min_balance_raw:
                    try:
                        min_balance = float(min_balance_raw.replace(",", "."))
                    except ValueError:
                        flash("Невірний формат мінімального залишку.", "error")
                        return redirect(url_for("admin_containers"))

                token = secrets.token_urlsafe(16)
                db.execute(
                    """
                    INSERT INTO containers (material_id, location_id, qr_token, min_balance)
                    VALUES (?, ?, ?, ?);
                    """,
                    (material_id, location_id, token, min_balance),
                )
                db.commit()
                flash("Ємність додано.", "success")

        elif action == "update_location":
            container_id = request.form.get("container_id")
            location_id = request.form.get("location_id")
            if not container_id or not location_id:
                flash("Необхідно вказати ємність і локацію.", "error")
            else:
                db.execute(
                    "UPDATE containers SET location_id = ? WHERE id = ?;",
                    (location_id, container_id),
                )
                db.commit()
                flash("Локацію ємності оновлено.", "success")

        elif action == "update_min":
            container_id = request.form.get("container_id")
            min_balance_raw = request.form.get("min_balance", "").strip()
            if not container_id:
                flash("Необхідно вказати ємність.", "error")
            else:
                if min_balance_raw == "":
                    db.execute(
                        "UPDATE containers SET min_balance = NULL WHERE id = ?;",
                        (container_id,),
                    )
                else:
                    try:
                        mb = float(min_balance_raw.replace(",", "."))
                    except ValueError:
                        flash("Невірний формат мінімального залишку.", "error")
                        return redirect(url_for("admin_containers"))
                    db.execute(
                        "UPDATE containers SET min_balance = ? WHERE id = ?;",
                        (mb, container_id),
                    )
                db.commit()
                flash("Мінімальний залишок оновлено.", "success")

        return redirect(url_for("admin_containers"))

    containers = get_containers_with_stock(
        location_id=selected_location_id,
        search=search_q,
        material_id=selected_material_id,
    )

    return render_template(
        "admin_containers.html",
        containers=containers,
        locations=locations,
        materials=materials,
        selected_location_id=selected_location_id,
        selected_material_id=selected_material_id,
        search_q=search_q,
    )


@app.route("/admin/containers/<int:container_id>/delete", methods=["POST"])
@login_required
def delete_container(container_id):
    db = get_db()
    db.execute("DELETE FROM transactions WHERE container_id = ?;", (container_id,))
    db.execute("DELETE FROM containers WHERE id = ?;", (container_id,))
    db.commit()

    logger.info("Deleted container id=%s and related transactions", container_id)
    flash("Ємність та всі її операції видалено.", "success")
    return redirect(url_for("admin_containers"))


@app.route("/container/<int:container_id>/qr")
def container_qr(container_id):
    db = get_db()
    row = db.execute(
        "SELECT id, qr_token FROM containers WHERE id = ?;",
        (container_id,),
    ).fetchone()
    if row is None:
        abort(404)

    qr_token = row["qr_token"]
    if not qr_token:
        qr_token = secrets.token_urlsafe(16)
        db.execute(
            "UPDATE containers SET qr_token = ? WHERE id = ?;",
            (qr_token, container_id),
        )
        db.commit()

    use_url = url_for("use_material", token=qr_token, _external=True)

    img = qrcode.make(use_url)
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")


@app.route("/admin/print_qr")
@login_required
def print_qr():
    db = get_db()
    locations = get_locations()
    location_id = request.args.get("location_id", type=int)
    size = request.args.get("size", "small")
    if size not in ("small", "medium", "large"):
        size = "small"

    containers = None
    if location_id:
        containers = db.execute(
            """
            SELECT
                c.id,
                c.qr_token,
                m.code AS material_code,
                m.name AS material_name,
                l.name AS location_name
            FROM containers c
            JOIN materials m ON c.material_id = m.id
            JOIN locations l ON c.location_id = l.id
            WHERE c.location_id = ?
            ORDER BY m.code, c.id;
            """,
            (location_id,),
        ).fetchall()

    return render_template(
        "admin_print_qr.html",
        locations=locations,
        containers=containers,
        selected_location_id=location_id,
        size=size,
    )


# ----------------- Історія ємності -----------------


@app.route("/admin/containers/<int:container_id>/history")
@login_required
def container_history(container_id):
    db = get_db()

    container = db.execute(
        """
        SELECT
            c.id AS container_id,
            c.min_balance,
            c.material_id,
            c.location_id,
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
        WHERE c.id = ?
        GROUP BY
            c.id,
            c.min_balance,
            c.material_id,
            c.location_id,
            m.code,
            m.name,
            m.unit,
            l.name;
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

    if date_from:
        conditions.append("t.created_at >= ?")
        params.append(date_from + "T00:00:00")

    if date_to:
        conditions.append("t.created_at <= ?")
        params.append(date_to + "T23:59:59")

    if direction in ("IN", "OUT"):
        conditions.append("t.direction = ?")
        params.append(direction)

    if worker_id:
        conditions.append("w.id = ?")
        params.append(worker_id)

    where_clause = "WHERE " + " AND ".join(conditions)

    history_rows = db.execute(
        f"""
        SELECT
            t.id,
            t.created_at,
            t.direction,
            t.qty,
            t.job,
            t.is_service,
            w.name AS worker_name
        FROM transactions t
        LEFT JOIN workers w ON t.worker_id = w.id
        {where_clause}
        ORDER BY t.created_at DESC, t.id DESC;
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
        selected_worker_id=selected_worker_id,
        filters=filters,
    )


@app.route("/admin/containers/<int:container_id>/history/export")
@login_required
def export_container_history(container_id):
    db = get_db()

    date_from = request.args.get("date_from") or None
    date_to = request.args.get("date_to") or None
    direction = request.args.get("direction") or None
    worker_id = request.args.get("worker_id") or None

    conditions = ["t.container_id = ?"]
    params = [container_id]

    if date_from:
        conditions.append("t.created_at >= ?")
        params.append(date_from + "T00:00:00")

    if date_to:
        conditions.append("t.created_at <= ?")
        params.append(date_to + "T23:59:59")

    if direction in ("IN", "OUT"):
        conditions.append("t.direction = ?")
        params.append(direction)

    if worker_id:
        conditions.append("w.id = ?")
        params.append(worker_id)

    where_clause = "WHERE " + " AND ".join(conditions)

    rows = db.execute(
        f"""
        SELECT
            t.id,
            t.created_at,
            t.direction,
            t.qty,
            t.job,
            t.is_service,
            w.name AS worker_name
        FROM transactions t
        LEFT JOIN workers w ON t.worker_id = w.id
        {where_clause}
        ORDER BY t.created_at DESC, t.id DESC;
        """,
        params,
    ).fetchall()

    output = StringIO()
    writer = csv.writer(output, delimiter=";")
    writer.writerow(["ID", "Дата/час", "Тип", "Кількість", "Працівник", "Замовлення/робота", "Службова"])
    for r in rows:
        writer.writerow(
            [
                r["id"],
                localtime_filter(r["created_at"]),
                r["direction"],
                f"{r['qty']:.3f}",
                r["worker_name"] or "",
                r["job"] or "",
                "так" if r["is_service"] else "",
            ]
        )

    output.seek(0)
    return Response(
        output.getvalue().encode("utf-8-sig"),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="container_{container_id}_history.csv"'},
    )


@app.route("/admin/containers/<int:container_id>/service", methods=["POST"])
@login_required
def create_service_transaction(container_id):
    db = get_db()
    direction = request.form.get("direction")
    qty_raw = request.form.get("qty", "").strip()
    job = request.form.get("job", "").strip() or None

    if direction not in ("IN", "OUT"):
        flash("Невірний тип операції.", "error")
        return redirect(url_for("container_history", container_id=container_id))

    try:
        qty = float(qty_raw.replace(",", "."))
    except ValueError:
        flash("Невірний формат кількості.", "error")
        return redirect(url_for("container_history", container_id=container_id))

    if qty <= 0:
        flash("Кількість має бути більшою за 0.", "error")
        return redirect(url_for("container_history", container_id=container_id))

    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        """
        INSERT INTO transactions (created_at, worker_id, container_id, qty, direction, job, is_service)
        VALUES (?, NULL, ?, ?, ?, ?, 1);
        """,
        (now, container_id, qty, direction, job),
    )
    db.commit()
    flash("Службову операцію додано.", "success")
    return redirect(url_for("container_history", container_id=container_id))


# ----------------- Прихід матеріалу -----------------


@app.route("/admin/material_in", methods=["GET", "POST"])
@login_required
def admin_material_in():
    db = get_db()
    materials = get_materials()

    if request.method == "POST":
        material_id = request.form.get("material_id")
        job = request.form.get("job", "").strip() or None
        if not material_id:
            flash("Не вибрано матеріал.", "error")
            return redirect(url_for("admin_material_in"))

        containers = db.execute(
            """
            SELECT
                c.id,
                COALESCE(SUM(
                    CASE
                        WHEN t.direction = 'IN' THEN t.qty
                        WHEN t.direction = 'OUT' THEN -t.qty
                    END
                ), 0) AS balance
            FROM containers c
            LEFT JOIN transactions t ON t.container_id = c.id
            WHERE c.material_id = ?
            GROUP BY c.id
            ORDER BY c.id;
            """,
            (material_id,),
        ).fetchall()

        total_added = 0.0
        now = datetime.now(timezone.utc).isoformat()
        worker_id = session.get("worker_id")

        for c in containers:
            field_name = f"qty_{c['id']}"
            raw = request.form.get(field_name, "").strip()
            if not raw:
                continue
            try:
                qty = float(raw.replace(",", "."))
            except ValueError:
                flash(f"Невірний формат кількості для ємності {c['id']}.", "error")
                return redirect(url_for("admin_material_in", material_id=material_id))
            if qty <= 0:
                continue

            db.execute(
                """
                INSERT INTO transactions (created_at, worker_id, container_id, qty, direction, job, is_service)
                VALUES (?, ?, ?, ?, 'IN', ?, 0);
                """,
                (now, worker_id, c["id"], qty, job),
            )
            total_added += qty

        db.commit()
        flash(f"Прихід збережено. Додано {total_added:.3f} одиниць.", "success")
        return redirect(url_for("admin_material_in", material_id=material_id))

    material_id = request.args.get("material_id", type=int)
    selected_material = None
    material_balance = None
    containers = []

    if material_id:
        selected_material = db.execute(
            "SELECT * FROM materials WHERE id = ?;",
            (material_id,),
        ).fetchone()

        if selected_material:
            material_balance = db.execute(
                """
                SELECT
                    COALESCE(SUM(
                        CASE
                            WHEN t.direction = 'IN' THEN t.qty
                            WHEN t.direction = 'OUT' THEN -t.qty
                        END
                    ), 0) AS balance
                FROM containers c
                LEFT JOIN transactions t ON t.container_id = c.id
                WHERE c.material_id = ?;
                """,
                (material_id,),
            ).fetchone()

            containers = db.execute(
                """
                SELECT
                    c.id,
                    l.name AS location_name,
                    COALESCE(SUM(
                        CASE
                            WHEN t.direction = 'IN' THEN t.qty
                            WHEN t.direction = 'OUT' THEN -t.qty
                        END
                    ), 0) AS balance
                FROM containers c
                JOIN locations l ON c.location_id = l.id
                LEFT JOIN transactions t ON t.container_id = c.id
                WHERE c.material_id = ?
                GROUP BY c.id, l.name
                ORDER BY l.name, c.id;
                """,
                (material_id,),
            ).fetchall()

    return render_template(
        "admin_material_in.html",
        materials=materials,
        selected_material=selected_material,
        material_balance=material_balance,
        containers=containers,
    )


# ----------------- Прихід напряму в ємність -----------------


@app.route("/admin/stock", methods=["GET", "POST"])
@login_required
def admin_stock():
    db = get_db()

    if request.method == "POST":
        container_id = request.form.get("container_id")
        qty_raw = request.form.get("qty", "").strip()
        job = request.form.get("job", "").strip() or None

        if not container_id:
            flash("Необхідно вибрати ємність.", "error")
            return redirect(url_for("admin_stock"))
        try:
            qty = float(qty_raw.replace(",", "."))
        except ValueError:
            flash("Невірний формат кількості.", "error")
            return redirect(url_for("admin_stock"))

        if qty <= 0:
            flash("Кількість має бути більшою за 0.", "error")
            return redirect(url_for("admin_stock"))

        now = datetime.now(timezone.utc).isoformat()
        worker_id = session.get("worker_id")

        db.execute(
            """
            INSERT INTO transactions (created_at, worker_id, container_id, qty, direction, job, is_service)
            VALUES (?, ?, ?, ?, 'IN', ?, 0);
            """,
            (now, worker_id, container_id, qty, job),
        )
        db.commit()
        flash("Прихід у ємність збережено.", "success")
        return redirect(url_for("admin_stock"))

    containers = get_containers_with_stock()
    return render_template("admin_stock.html", containers=containers)


# ----------------- Інвентаризація -----------------


@app.route("/admin/inventory", methods=["GET", "POST"])
@login_required
def admin_inventory():
    db = get_db()
    locations = get_locations()
    materials = get_materials()

    if request.method == "POST":
        location_id = request.form.get("location_id") or None
        material_id = request.form.get("material_id") or None
        note = request.form.get("note", "").strip() or None

        now_utc = datetime.now(timezone.utc).isoformat()
        now_local_str = datetime.now(LOCAL_TZ).strftime("%Y-%m-%d %H:%M")
        adjustments = 0

        for key, val in request.form.items():
            if not key.startswith("fact_"):
                continue
            cid_str = key.split("_", 1)[1]
            val = val.strip()
            if not val:
                continue
            try:
                container_id = int(cid_str)
            except ValueError:
                continue
            try:
                fact = float(val.replace(",", "."))
            except ValueError:
                flash(f"Невірний формат фактичного залишку для ємності {cid_str}.", "error")
                return redirect(
                    url_for(
                        "admin_inventory",
                        location_id=location_id,
                        material_id=material_id,
                    )
                )

            row = db.execute(
                """
                SELECT COALESCE(SUM(
                    CASE
                        WHEN direction = 'IN' THEN qty
                        WHEN direction = 'OUT' THEN -qty
                    END
                ), 0) AS balance
                FROM transactions
                WHERE container_id = ?;
                """,
                (container_id,),
            ).fetchone()
            current_balance = float(row["balance"] or 0.0)

            diff = fact - current_balance
            if diff == 0:
                continue

            direction = "IN" if diff > 0 else "OUT"
            qty = abs(diff)

            job = f"Інвентаризація {now_local_str}"
            if note:
                job += f": {note}"

            db.execute(
                """
                INSERT INTO transactions (created_at, worker_id, container_id, qty, direction, job, is_service)
                VALUES (?, NULL, ?, ?, ?, ?, 1);
                """,
                (now_utc, container_id, qty, direction, job),
            )
            adjustments += 1

        db.commit()
        flash(f"Інвентаризацію виконано. Скориговано {adjustments} ємностей.", "success")
        return redirect(
            url_for(
                "admin_inventory",
                location_id=location_id,
                material_id=material_id,
            )
        )

    location_id = request.args.get("location_id", type=int)
    material_id = request.args.get("material_id", type=int)

    containers = get_containers_with_stock(
        location_id=location_id,
        material_id=material_id,
    )

    return render_template(
        "admin_inventory.html",
        locations=locations,
        materials=materials,
        containers=containers,
        selected_location_id=location_id,
        selected_material_id=material_id,
    )


# ----------------- Журнал операцій -----------------


@app.route("/admin/transactions", methods=["GET"])
@login_required
def admin_transactions():
    db = get_db()

    page = request.args.get("page", 1, type=int)
    per_page = 200

    date_from = request.args.get("date_from") or None
    date_to = request.args.get("date_to") or None
    worker_id = request.args.get("worker_id") or None
    material_id = request.args.get("material_id") or None
    direction = request.args.get("direction") or None
    q = request.args.get("q", "").strip() or None
    storno_flag = request.args.get("storno") == "1"
    service_flag = request.args.get("service") == "1"

    conditions = []
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

    if material_id:
        conditions.append("m.id = ?")
        params.append(material_id)

    if direction in ("IN", "OUT"):
        conditions.append("t.direction = ?")
        params.append(direction)

    if q:
        pattern = f"%{q}%"
        conditions.append(
            "(m.code LIKE ? OR m.name LIKE ? OR l.name LIKE ? OR w.name LIKE ? OR t.job LIKE ?)"
        )
        params.extend([pattern, pattern, pattern, pattern, pattern])

    if storno_flag:
        conditions.append("(t.job LIKE 'СТОРНО %' OR t.job LIKE 'STORNO %')")

    if service_flag:
        conditions.append("t.is_service = 1")

    where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""

    offset = (page - 1) * per_page
    query = f"""
        SELECT
            t.id,
            t.created_at,
            t.direction,
            t.qty,
            t.job,
            t.is_service,
            m.code AS material_code,
            m.name AS material_name,
            m.unit AS material_unit,
            w.name AS worker_name,
            l.name AS location_name
        FROM transactions t
        JOIN containers c ON t.container_id = c.id
        JOIN materials m ON c.material_id = m.id
        JOIN locations l ON c.location_id = l.id
        LEFT JOIN workers w ON t.worker_id = w.id
        {where_clause}
        ORDER BY t.created_at DESC, t.id DESC
        LIMIT ? OFFSET ?;
    """
    rows = db.execute(query, (*params, per_page + 1, offset)).fetchall()

    has_next = len(rows) > per_page
    transactions = rows[:per_page]

    workers = get_workers()
    materials = get_materials()

    selected_worker_id = int(worker_id) if worker_id else None
    selected_material_id = int(material_id) if material_id else None

    filters = {
        "date_from": date_from,
        "date_to": date_to,
        "worker_id": worker_id,
        "material_id": material_id,
        "direction": direction,
        "q": q,
        "storno_only": storno_flag,
        "service_only": service_flag,
    }

    return render_template(
        "admin_transactions.html",
        transactions=transactions,
        workers=workers,
        materials=materials,
        filters=filters,
        page=page,
        has_next=has_next,
        selected_worker_id=selected_worker_id,
        selected_material_id=selected_material_id,
    )


@app.route("/admin/transactions/<int:tx_id>/reverse", methods=["POST"])
@login_required
def reverse_transaction(tx_id):
    db = get_db()
    tx = db.execute(
        """
        SELECT id, created_at, worker_id, container_id, qty, direction, job
        FROM transactions
        WHERE id = ?;
        """,
        (tx_id,),
    ).fetchone()

    if tx is None:
        flash("Операцію не знайдено.", "error")
        return redirect(url_for("admin_transactions"))

    new_direction = "OUT" if tx["direction"] == "IN" else "IN"
    now = datetime.now(timezone.utc).isoformat()
    new_job = f"СТОРНО #{tx['id']}"
    if tx["job"]:
        new_job += f" ({tx['job']})"

    db.execute(
        """
        INSERT INTO transactions (created_at, worker_id, container_id, qty, direction, job, is_service)
        VALUES (?, ?, ?, ?, ?, ?, 1);
        """,
        (now, tx["worker_id"], tx["container_id"], tx["qty"], new_direction, new_job),
    )
    db.commit()

    flash(f"Створено сторно для операції #{tx_id}.", "success")
    return redirect(url_for("admin_transactions"))


# ----------------- Пошук -----------------


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
            ORDER BY CAST(code AS INTEGER) ASC, code ASC;
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


# ----------------- Списання по QR -----------------


@app.route("/use/<token>", methods=["GET", "POST"])
def use_material(token):
    db = get_db()
    container = db.execute(
        """
        SELECT
            c.id AS container_id,
            c.min_balance,
            c.qr_token,
            m.id AS material_id,
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
        GROUP BY
            c.id,
            c.min_balance,
            c.qr_token,
            m.id,
            m.code,
            m.name,
            m.unit,
            l.name;
        """,
        (token,),
    ).fetchone()

    if container is None:
        return render_template("use_material.html", container=None, workers=[], current_worker=None), 404

    workers = get_workers()
    current_worker = None
    worker_id_session = session.get("worker_id")
    if worker_id_session:
        current_worker = db.execute(
            "SELECT * FROM workers WHERE id = ?;",
            (worker_id_session,),
        ).fetchone()

    if request.method == "POST":
        qty_raw = request.form.get("qty", "").strip()
        job = request.form.get("job", "").strip() or None

        worker_id = worker_id_session
        if not worker_id:
            pin = request.form.get("pin", "").strip()
            worker_id_form = request.form.get("worker_id") or None

            if pin:
                row = db.execute(
                    "SELECT id FROM workers WHERE pin = ?;",
                    (pin,),
                ).fetchone()
                if not row:
                    flash("Працівника з таким PIN не знайдено.", "error")
                    return redirect(url_for("use_material", token=token))
                worker_id = row["id"]
            elif worker_id_form:
                worker_id = int(worker_id_form)
            else:
                flash("Необхідно обрати працівника або вказати PIN.", "error")
                return redirect(url_for("use_material", token=token))

        try:
            qty = float(qty_raw.replace(",", "."))
        except ValueError:
            flash("Невірний формат кількості.", "error")
            return redirect(url_for("use_material", token=token))

        if qty <= 0:
            flash("Кількість має бути більшою за 0.", "error")
            return redirect(url_for("use_material", token=token))

        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            """
            INSERT INTO transactions (created_at, worker_id, container_id, qty, direction, job, is_service)
            VALUES (?, ?, ?, ?, 'OUT', ?, 0);
            """,
            (now, worker_id, container["container_id"], qty, job),
        )
        db.commit()

        flash("Матеріал успішно списано.", "success")
        return redirect(url_for("use_material", token=token))

    return render_template(
        "use_material.html",
        container=container,
        workers=workers,
        current_worker=current_worker,
    )


@app.route("/scan")
def scan():
    return render_template("scan.html")


# ----------------- Запуск -----------------


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
