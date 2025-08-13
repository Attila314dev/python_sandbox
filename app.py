import os
from flask import Flask, render_template, request, redirect, url_for, session
from sqlalchemy import create_engine, text
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-only-change-me")

DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_size=2, max_overflow=0)
ph = PasswordHasher()

@app.get("/")
def home():
    return render_template("index.html")

@app.get("/health")
def health():
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"ok": True, "db": "connected"}
    except Exception as e:
        return {"ok": False, "error": str(e)}

@app.get("/test-session")
def test_session():
    session["ping"] = "pong"
    return {"ok": True}

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    if not email or not password:
        return {"ok": False, "error": "missing email or password"}, 400

    # user lekérés
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT id, password_hash, role FROM users WHERE email = :email LIMIT 1"),
            {"email": email}
        ).mappings().first()

    if not row:
        return {"ok": False, "error": "invalid credentials"}, 401

    try:
        ph.verify(row["password_hash"], password)
    except VerifyMismatchError:
        return {"ok": False, "error": "invalid credentials"}, 401

    # ✅ sikeres bejelentkezés
    session["user_id"] = row["id"]
    session["email"] = email
    session["role"] = row["role"]
    return redirect(url_for("home"))

@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))
