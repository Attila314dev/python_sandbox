import os
from flask import Flask, render_template, request, redirect, url_for
from sqlalchemy import create_engine, text
from argon2 import PasswordHasher

app = Flask(__name__)

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

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""

    if not email or not password:
        return {"ok": False, "error": "missing email or password"}, 400

    pwd_hash = ph.hash(password)

    try:
        with engine.begin() as conn:
            conn.execute(
                text("""
                    INSERT INTO users (email, password_hash)
                    VALUES (:email, :password_hash)
                """),
                {"email": email, "password_hash": pwd_hash},
            )
    except Exception:
        return {"ok": False, "error": "email already exists or db error"}, 400

    return redirect(url_for("home"))
