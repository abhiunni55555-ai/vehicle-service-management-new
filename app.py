import os
from functools import wraps

import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify
)
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-this-secret-key")

# Connect to your EXISTING PostgreSQL database
DB_CONFIG = {
    "host": os.environ["DB_HOST"],
    "port":  os.environ["DB_PORT"],
    "dbname": os.environ["DB_NAME"],
    "user": os.environ["DB_USER"],
    "password": os.environ["DB_PASSWORD"]
}

# Existing tables and their primary keys
TABLES = {
    "customers": {
        "pk": "customer_id",
        "columns": [
            "customer_id",
            "customer_name", "phone", "email", "address"
        ]
    },
    "vehicles": {
        "pk": "vehicle_id",
        "columns": [
            "customer_id", "vehicle_number", "brand",
            "model", "manufacture_year"
        ]
    },
    "mechanics": {
        "pk": "mechanic_id",
        "columns": [
            "mechanic_name", "phone", "specialization"
        ]
    },
    "services": {
        "pk": "service_id",
        "columns": ["service_name","description","service_cost"]
    },
    "service_bookings": {
        "pk": "booking_id",
        "columns": [
            "vehicle_id", "service_id", "mechanic_id",
            "booking_date", "status"
        ]
    },
    "spare_parts": {
        "pk": "part_id",
        "columns": ["part_name", "quantity", "price"]
    },
    "bills": {
        "pk": "bill_id",
        "columns": ["booking_id", "bill_date", "total_amount"]
    },
    "payments": {
        "pk": "payment_id",
        "columns": [
            "bill_id", "payment_date", "amount", "payment_method"
        ]
    },
    "users": {
        "pk": "id",
        "columns": ["user_id", "password_hash", "role"]
    }
}


def get_db_connection():
    if not DB_CONFIG["password"]:
        raise RuntimeError(
            "Database password is missing. Set the DB_PASSWORD environment variable."
        )
    return psycopg.connect(**DB_CONFIG, row_factory=dict_row)


def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Please log in first."}), 401
            return redirect(url_for("home"))
        return function(*args, **kwargs)
    return wrapper


def admin_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Please log in first."}), 401

        if session.get("role") != "admin":
            return jsonify({"error": "Administrator access required."}), 403

        return function(*args, **kwargs)
    return wrapper


@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET","POST"])
def home():
    if request.method == "POST":
        user_id = request.form.get("user_id", "").strip()
        password = request.form.get("password", "")

        try:
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT user_id, password_hash, role
                        FROM users
                        WHERE user_id = %s
                        """,
                        (user_id,)
                    )
                    user = cur.fetchone()

            if user and check_password_hash(
                user["password_hash"], password
            ):
                session.clear()
                session["user_id"] = user["user_id"]
                session["role"] = user["role"]
                return redirect(url_for("dashboard"))

            return render_template(
                "login.html",
                error="Invalid user ID or password."
            ), 401

        except Exception:
            app.logger.exception("Login error")
            return render_template(
                "login.html",
                error="Could not connect to the database. Check the configuration."
            ), 500

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("index.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/api/tables")
@login_required
def list_tables():
    return jsonify({
        "tables": list(TABLES.keys()),
        "role": session.get("role")
    })


@app.route("/api/<table_name>", methods=["GET"])
@login_required
def get_records(table_name):
    if table_name not in TABLES:
        return jsonify({"error": "Unknown table."}), 404

    table = TABLES[table_name]

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    sql.SQL("SELECT * FROM {} ORDER BY {}").format(
                        sql.Identifier(table_name),
                        sql.Identifier(table["pk"])
                    )
                )
                records = cur.fetchall()

        # Never return password hashes to the browser.
        if table_name == "users":
            records = [
                {
                    "id": row["id"],
                    "user_id": row["user_id"],
                    "role": row["role"]
                }
                for row in records
            ]

        return jsonify(records)

    except Exception:
        app.logger.exception("Read error")
        return jsonify({"error": "Could not read records."}), 500


@app.route("/api/<table_name>", methods=["POST"])
@admin_required
def add_record(table_name):
    if table_name not in TABLES:
        return jsonify({"error": "Unknown table."}), 404

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Send the record as JSON."}), 400

    table = TABLES[table_name]
    allowed = table["columns"]

    # CUSTOMER
    if table_name == "customers":
        data["customer_name"] = (
            data.get("customer_name")
            or data.get("customerName")
            or data.get("name")
        )

    # VEHICLES
    elif table_name == "vehicles":
        data["vehicle_number"] = (
            data.get("vehicle_number")
            or data.get("vehicleNumber")
        )
        data["customer_id"] = (
            data.get("customer_id")
            or data.get("customerId")
        )

    # MECHANICS
    elif table_name == "mechanics":
        data["mechanic_name"] = (
            data.get("mechanic_name")
            or data.get("mechanicName")
            or data.get("name")
        )

    # SERVICES
    elif table_name == "services":
        data["service_name"] = (
            data.get("service_name")
            or data.get("serviceName")
            or data.get("name")
        )
        data["service_cost"] = (
            data.get("service_cost")
            or data.get("serviceCost")
            or data.get("cost")
        )

    # SERVICE BOOKINGS
    elif table_name == "service_bookings":
        data["vehicle_id"] = (
            data.get("vehicle_id")
            or data.get("vehicleId")
        )
        data["service_id"] = (
            data.get("service_id")
            or data.get("serviceId")
        )
        data["mechanic_id"] = (
            data.get("mechanic_id")
            or data.get("mechanicId")
        )
        data["booking_date"] = (
            data.get("booking_date")
            or data.get("bookingDate")
        )

    # SPARE PARTS
    elif table_name == "spare_parts":
        data["part_name"] = (
            data.get("part_name")
            or data.get("partName")
            or data.get("name")
        )

    # BILLS
    elif table_name == "bills":
        data["booking_id"] = (
            data.get("booking_id")
            or data.get("bookingId")
        )
        data["total_amount"] = (
            data.get("total_amount")
            or data.get("totalAmount")
        )
        data["bill_date"] = (
            data.get("bill_date")
            or data.get("billDate")
        )

    # PAYMENTS
    elif table_name == "payments":
        data["bill_id"] = (
            data.get("bill_id")
            or data.get("billId")
        )
        data["payment_date"] = (
            data.get("payment_date")
            or data.get("paymentDate")
        )
        data["payment_method"] = (
            data.get("payment_method")
            or data.get("paymentMethod")
        )

    # USERS
    elif table_name == "users":
        data["user_id"] = (
            data.get("user_id")
            or data.get("userId")
        )
        password = data.get("password", "")
        if not password:
            return jsonify({"error": "A password is required for a new user."}), 400
        data["password_hash"] = generate_password_hash(password)

    fields = [key for key in allowed if key in data]

    if not fields:
        return jsonify({"error": "No valid fields were provided."}), 400

    values = [data[key] for key in fields]
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    sql.SQL("INSERT INTO {} ({}) VALUES ({}) RETURNING {}").format(
                        sql.Identifier(table_name),
                        sql.SQL(", ").join(map(sql.Identifier, fields)),
                        sql.SQL(", ").join(sql.Placeholder() for _ in fields),
                        sql.Identifier(table["pk"])
                    ),
                    values
                )
                result = cur.fetchone()

        return jsonify({
            "message": "Record added successfully.",
            "id": result[table["pk"]]
        }), 201

    except Exception:
        app.logger.exception("Insert error")
        return jsonify({
            "error": "Could not add the record. Check required fields and related IDs."
        }), 400


@app.route("/api/<table_name>/<int:record_id>", methods=["PUT"])
@admin_required
def update_record(table_name, record_id):
    if table_name not in TABLES:
        return jsonify({"error": "Unknown table."}), 404

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Send the updated record as JSON."}), 400

    table = TABLES[table_name]
    allowed = table["columns"]

    if table_name == "users" and data.get("password"):
        data["password_hash"] = generate_password_hash(data["password"])

    fields = [
        key for key in allowed
        if key in data and not (table_name == "users" and key == "password_hash"
                                and "password" not in data)
    ]

    if not fields:
        return jsonify({"error": "No valid fields were provided."}), 400

    values = [data[key] for key in fields]

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    sql.SQL("UPDATE {} SET {} WHERE {} = %s").format(
                        sql.Identifier(table_name),
                        sql.SQL(", ").join(
                            sql.SQL("{} = %s").format(sql.Identifier(field))
                            for field in fields
                        ),
                        sql.Identifier(table["pk"])
                    ),
                    values + [record_id]
                )

                if cur.rowcount == 0:
                    return jsonify({"error": "Record not found."}), 404

        return jsonify({"message": "Record updated successfully."})

    except Exception:
        app.logger.exception("Update error")
        return jsonify({
            "error": "Could not update the record. Check values and related IDs."
        }), 400


@app.route("/api/<table_name>/<int:record_id>", methods=["DELETE"])
@admin_required
def delete_record(table_name, record_id):
    if table_name not in TABLES:
        return jsonify({"error": "Unknown table."}), 404

    table = TABLES[table_name]

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    sql.SQL("DELETE FROM {} WHERE {} = %s").format(
                        sql.Identifier(table_name),
                        sql.Identifier(table["pk"])
                    ),
                    (record_id,)
                )

                if cur.rowcount == 0:
                    return jsonify({"error": "Record not found."}), 404

        return jsonify({"message": "Record deleted successfully."})

    except Exception:
        app.logger.exception("Delete error")
        return jsonify({
            "error": "Could not delete the record. Another record may depend on it."
        }), 400


@app.route("/api/test-db")
@login_required
def test_db():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT current_database() AS database_name")
                result = cur.fetchone()

        return jsonify({
            "status": "connected",
            "database": result["database_name"]
        })

    except Exception:
        app.logger.exception("Database test failed")
        return jsonify({"status": "error", "message": "Database connection failed."}), 500

@app.route("/api/dashboard-stats")
@login_required
def dashboard_stats():

    try:
        counts = {}

        with get_db_connection() as conn:
            with conn.cursor() as cur:

                tables = {
                    "customers": "customers",
                    "vehicles": "vehicles",
                    "bookings": "service_bookings",
                    "bills": "bills"
                }

                for key, table in tables.items():
                    cur.execute(
                        "SELECT to_regclass(%s)",
                        ("public." + table,)
                    )

                    if cur.fetchone()["to_regclass"] is None:
                        counts[key] = 0
                    else:
                        cur.execute(
                            sql.SQL("SELECT COUNT(*) AS count FROM {}").format(
                                sql.Identifier(table)
                            )
                        )
                        counts[key] = cur.fetchone()["count"]

        return jsonify(counts)

    except Exception as e:
        app.logger.exception("Dashboard count error")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
