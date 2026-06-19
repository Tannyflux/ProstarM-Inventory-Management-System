from __future__ import annotations

import sqlite3
import os
from datetime import date, datetime
from functools import wraps
from pathlib import Path

from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "instance" / "inventory.db"
COMPANY_NAME = "Prostarm Info Systems Limited"
COMPANY_LOCATION = "Mahape, Navi Mumbai"
DEFAULT_USERNAME = "TannyFlux"
DEFAULT_PASSWORD = "Admin@123"

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("IMS_SECRET_KEY", "change-this-secret-key")


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        DATABASE.parent.mkdir(exist_ok=True)
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(error: Exception | None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS materials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            code TEXT NOT NULL UNIQUE,
            serial_number TEXT NOT NULL UNIQUE,
            category TEXT,
            unit TEXT NOT NULL DEFAULT 'Nos',
            location TEXT,
            rack_number TEXT,
            unit_price REAL NOT NULL DEFAULT 0,
            reorder_level INTEGER NOT NULL DEFAULT 0,
            cell_serial_number TEXT,
            battery_pack_number TEXT,
            bms_number TEXT,
            warranty_until TEXT,
            notes TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            material_id INTEGER NOT NULL,
            tx_type TEXT NOT NULL CHECK (tx_type IN ('IN', 'OUT')),
            tx_date TEXT NOT NULL,
            quantity REAL NOT NULL CHECK (quantity > 0),
            grn_invoice_no TEXT,
            supplier_name TEXT,
            department_user TEXT,
            purpose TEXT,
            serial_number TEXT,
            remarks TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (material_id) REFERENCES materials(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            full_name TEXT,
            role TEXT NOT NULL DEFAULT 'user',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
    admin = db.execute("SELECT id FROM users WHERE username = ?", (DEFAULT_USERNAME,)).fetchone()
    if admin is None:
        db.execute(
            """
            INSERT INTO users (username, password_hash, full_name, role)
            VALUES (?, ?, ?, ?)
            """,
            (
                DEFAULT_USERNAME,
                generate_password_hash(DEFAULT_PASSWORD),
                "Administrator",
                "admin",
            ),
        )
    db.commit()


@app.before_request
def ensure_schema() -> None:
    init_db()
    public_endpoints = {"login", "static"}
    if request.endpoint not in public_endpoints and "user_id" not in session:
        return redirect(url_for("login", next=request.full_path))


@app.context_processor
def inject_branding():
    return {
        "company_name": COMPANY_NAME,
        "company_location": COMPANY_LOCATION,
        "current_user": session.get("username"),
        "is_admin": session.get("role") == "admin",
    }


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.full_path))
        return view(*args, **kwargs)

    return wrapped_view


def admin_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.full_path))
        if session.get("role") != "admin":
            flash("Only admin users can manage login IDs.", "error")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)

    return wrapped_view


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = form_value("username")
        password = form_value("password")
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ? AND is_active = 1",
            (username,),
        ).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            flash("Logged in successfully.", "success")
            next_url = request.args.get("next") or url_for("dashboard")
            return redirect(next_url)
        flash("Invalid login ID or password.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for("login"))


@app.route("/users", methods=["GET", "POST"])
@admin_required
def users():
    db = get_db()
    if request.method == "POST":
        username = form_value("username")
        password = form_value("password")
        full_name = form_value("full_name")
        role = form_value("role", "user")
        if not username or not password:
            flash("Login ID and password are required.", "error")
            return redirect(url_for("users"))
        try:
            db.execute(
                """
                INSERT INTO users (username, password_hash, full_name, role)
                VALUES (?, ?, ?, ?)
                """,
                (username, generate_password_hash(password), full_name, role),
            )
            db.commit()
            flash("Login ID created successfully.", "success")
        except sqlite3.IntegrityError:
            flash("That login ID already exists.", "error")
        return redirect(url_for("users"))

    user_rows = db.execute(
        """
        SELECT id, username, full_name, role, is_active, created_at
        FROM users
        ORDER BY role = 'admin' DESC, username
        """
    ).fetchall()
    return render_template("users.html", users=user_rows)


@app.post("/users/<int:user_id>/toggle")
@admin_required
def user_toggle(user_id: int):
    if user_id == session.get("user_id"):
        flash("You cannot deactivate your own login ID.", "error")
        return redirect(url_for("users"))
    db = get_db()
    db.execute(
        "UPDATE users SET is_active = CASE WHEN is_active = 1 THEN 0 ELSE 1 END WHERE id = ?",
        (user_id,),
    )
    db.commit()
    flash("User status updated.", "success")
    return redirect(url_for("users"))


@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if "user_id" not in session:
        return redirect(url_for("login", next=request.full_path))
    if request.method == "POST":
        current_password = form_value("current_password")
        new_password = form_value("new_password")
        confirm_password = form_value("confirm_password")
        if len(new_password) < 6:
            flash("New password must be at least 6 characters.", "error")
            return redirect(url_for("change_password"))
        if new_password != confirm_password:
            flash("New password and confirm password do not match.", "error")
            return redirect(url_for("change_password"))
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        if not user or not check_password_hash(user["password_hash"], current_password):
            flash("Current password is incorrect.", "error")
            return redirect(url_for("change_password"))
        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password), session["user_id"]),
        )
        db.commit()
        flash("Password changed successfully.", "success")
        return redirect(url_for("dashboard"))
    return render_template("change_password.html")


def stock_expression() -> str:
    return """
        (
            COALESCE(SUM(CASE WHEN t.tx_type = 'IN' THEN t.quantity ELSE 0 END), 0)
            - COALESCE(SUM(CASE WHEN t.tx_type = 'OUT' THEN t.quantity ELSE 0 END), 0)
        )
    """


def material_rows(where: str = "", params: tuple = ()) -> list[sqlite3.Row]:
    db = get_db()
    sql = f"""
        SELECT
            m.*,
            COALESCE(SUM(CASE WHEN t.tx_type = 'IN' THEN t.quantity ELSE 0 END), 0) AS stock_in,
            COALESCE(SUM(CASE WHEN t.tx_type = 'OUT' THEN t.quantity ELSE 0 END), 0) AS stock_out,
            {stock_expression()} AS available_stock,
            ({stock_expression()} * m.unit_price) AS stock_value
        FROM materials m
        LEFT JOIN transactions t ON t.material_id = m.id
        {where}
        GROUP BY m.id
        ORDER BY m.name
    """
    return db.execute(sql, params).fetchall()


def get_material(material_id: int) -> sqlite3.Row | None:
    rows = material_rows("WHERE m.id = ?", (material_id,))
    return rows[0] if rows else None


def form_value(name: str, default: str = "") -> str:
    return request.form.get(name, default).strip()


@app.route("/")
def dashboard():
    db = get_db()
    materials = material_rows()
    total_materials = len(materials)
    total_value = sum(row["stock_value"] or 0 for row in materials)
    low_stock = [row for row in materials if row["available_stock"] <= row["reorder_level"]]
    recent_transactions = db.execute(
        """
        SELECT t.*, m.name AS material_name, m.code AS material_code, m.location, m.rack_number
        FROM transactions t
        JOIN materials m ON m.id = t.material_id
        ORDER BY t.tx_date DESC, t.id DESC
        LIMIT 8
        """
    ).fetchall()
    return render_template(
        "dashboard.html",
        materials=materials,
        total_materials=total_materials,
        total_value=total_value,
        low_stock=low_stock,
        recent_transactions=recent_transactions,
    )


@app.route("/materials")
def materials():
    query = request.args.get("q", "").strip()
    where = ""
    params: tuple = ()
    if query:
        like = f"%{query}%"
        where = """
            WHERE m.name LIKE ?
               OR m.code LIKE ?
               OR m.serial_number LIKE ?
               OR m.cell_serial_number LIKE ?
               OR m.battery_pack_number LIKE ?
               OR m.bms_number LIKE ?
        """
        params = (like, like, like, like, like, like)
    return render_template("materials.html", materials=material_rows(where, params), query=query)


@app.route("/materials/new", methods=["GET", "POST"])
def material_new():
    if request.method == "POST":
        db = get_db()
        try:
            db.execute(
                """
                INSERT INTO materials (
                    name, code, serial_number, category, unit, location, rack_number,
                    unit_price, reorder_level, cell_serial_number, battery_pack_number,
                    bms_number, warranty_until, notes
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    form_value("name"),
                    form_value("code"),
                    form_value("serial_number"),
                    form_value("category"),
                    form_value("unit", "Nos"),
                    form_value("location"),
                    form_value("rack_number"),
                    float(form_value("unit_price", "0") or 0),
                    int(form_value("reorder_level", "0") or 0),
                    form_value("cell_serial_number"),
                    form_value("battery_pack_number"),
                    form_value("bms_number"),
                    form_value("warranty_until"),
                    form_value("notes"),
                ),
            )
            db.commit()
            flash("Material added successfully.", "success")
            return redirect(url_for("materials"))
        except sqlite3.IntegrityError as exc:
            flash(f"Material code and serial number must be unique. {exc}", "error")
    return render_template("material_form.html", material=None)


@app.route("/materials/<int:material_id>")
def material_detail(material_id: int):
    material = get_material(material_id)
    if material is None:
        flash("Material not found.", "error")
        return redirect(url_for("materials"))
    transactions = get_db().execute(
        """
        SELECT *
        FROM transactions
        WHERE material_id = ?
        ORDER BY tx_date DESC, id DESC
        """,
        (material_id,),
    ).fetchall()
    return render_template("material_detail.html", material=material, transactions=transactions)


@app.route("/stock-in", methods=["GET", "POST"])
def stock_in():
    if request.method == "POST":
        add_transaction("IN")
        return redirect(url_for("dashboard"))
    return render_template("transaction_form.html", tx_type="IN", materials=material_rows(), today=date.today().isoformat())


@app.route("/stock-out", methods=["GET", "POST"])
def stock_out():
    if request.method == "POST":
        material_id = int(form_value("material_id", "0") or 0)
        quantity = float(form_value("quantity", "0") or 0)
        material = get_material(material_id)
        if material is None:
            flash("Select a valid material.", "error")
            return redirect(url_for("stock_out"))
        if quantity > material["available_stock"]:
            flash("Cannot issue more than available stock.", "error")
            return redirect(url_for("stock_out"))
        add_transaction("OUT")
        return redirect(url_for("dashboard"))
    return render_template("transaction_form.html", tx_type="OUT", materials=material_rows(), today=date.today().isoformat())


def add_transaction(tx_type: str) -> None:
    db = get_db()
    material_id = int(form_value("material_id", "0") or 0)
    material = get_material(material_id)
    serial_number = form_value("serial_number") or (material["serial_number"] if material else "")
    db.execute(
        """
        INSERT INTO transactions (
            material_id, tx_type, tx_date, quantity, grn_invoice_no, supplier_name,
            department_user, purpose, serial_number, remarks
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            material_id,
            tx_type,
            form_value("tx_date", date.today().isoformat()),
            float(form_value("quantity", "0") or 0),
            form_value("grn_invoice_no"),
            form_value("supplier_name"),
            form_value("department_user"),
            form_value("purpose"),
            serial_number,
            form_value("remarks"),
        ),
    )
    db.commit()
    flash("Stock transaction saved.", "success")


@app.route("/search")
def search():
    query = request.args.get("q", "").strip()
    results = []
    if query:
        like = f"%{query}%"
        results = material_rows(
            """
            WHERE m.serial_number LIKE ?
               OR m.name LIKE ?
               OR m.code LIKE ?
               OR m.cell_serial_number LIKE ?
               OR m.battery_pack_number LIKE ?
               OR m.bms_number LIKE ?
            """,
            (like, like, like, like, like, like),
        )
    return render_template("search.html", query=query, results=results)


@app.route("/reports")
def reports():
    db = get_db()
    report_type = request.args.get("type", "stock")
    report_date = request.args.get("date", date.today().isoformat())
    selected_material = request.args.get("material_id", "")
    materials_list = material_rows()
    rows = []

    if report_type == "history" and selected_material:
        rows = db.execute(
            """
            SELECT t.*, m.name AS material_name, m.code AS material_code
            FROM transactions t
            JOIN materials m ON m.id = t.material_id
            WHERE m.id = ?
            ORDER BY t.tx_date DESC, t.id DESC
            """,
            (selected_material,),
        ).fetchall()
    elif report_type == "daily":
        rows = db.execute(
            """
            SELECT t.*, m.name AS material_name, m.code AS material_code
            FROM transactions t
            JOIN materials m ON m.id = t.material_id
            WHERE t.tx_date = ?
            ORDER BY t.id DESC
            """,
            (report_date,),
        ).fetchall()
    elif report_type == "serial":
        rows = db.execute(
            """
            SELECT t.*, m.name AS material_name, m.code AS material_code, m.serial_number AS master_serial
            FROM transactions t
            JOIN materials m ON m.id = t.material_id
            WHERE t.serial_number LIKE ? OR m.serial_number LIKE ?
            ORDER BY t.tx_date DESC, t.id DESC
            """,
            (f"%{request.args.get('serial', '').strip()}%", f"%{request.args.get('serial', '').strip()}%"),
        ).fetchall()
    else:
        rows = materials_list

    return render_template(
        "reports.html",
        report_type=report_type,
        report_date=report_date,
        selected_material=selected_material,
        materials=materials_list,
        rows=rows,
        serial=request.args.get("serial", "").strip(),
    )


@app.template_filter("money")
def money(value: float) -> str:
    return f"₹{value:,.2f}"


@app.template_filter("qty")
def qty(value: float) -> str:
    number = float(value or 0)
    if number.is_integer():
        return f"{int(number):,}"
    return f"{number:,.3f}".rstrip("0").rstrip(".")


@app.template_filter("nice_date")
def nice_date(value: str) -> str:
    try:
        return datetime.fromisoformat(value).strftime("%d %b %Y")
    except ValueError:
        return value


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
