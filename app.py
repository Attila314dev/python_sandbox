import os
from flask import Flask, render_template, request, redirect, url_for, session
from sqlalchemy import create_engine, text
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from functools import wraps
import secrets
import requests
from datetime import datetime, timedelta, timezone
from sqlalchemy.exc import IntegrityError

def make_verify_token():
    return secrets.token_urlsafe(32)

def send_verification_email(to_email: str, token: str):
    api_key = os.getenv("RESEND_API_KEY")
    from_email = os.getenv("FROM_EMAIL", "no-reply@resend.dev")
    base = os.getenv("APP_BASE_URL", "http://localhost:5000")
    link = f"{base}/verify?token={token}"

    payload = {
        "from": f"My Tutorial <{from_email}>",
        "to": [to_email],
        "subject": "Verify your email",
        "html": f"<p>Click to verify your account:</p><p><a href=\"{link}\">{link}</a></p>"
    }
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    try:
        requests.post("https://api.resend.com/emails", json=payload, headers=headers, timeout=10)
    except Exception:
        pass  # nem dobjuk el a folyamatot, max nem megy ki a levél

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-only-change-me")
app.config.update(
    SESSION_COOKIE_SECURE=True,      # csak HTTPS-en
    SESSION_COOKIE_HTTPONLY=True,    # JS ne lássa
    SESSION_COOKIE_SAMESITE="Lax",   # CSRF ellen alap
    PERMANENT_SESSION_LIFETIME=3600, # 1 óra
)


DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_size=2, max_overflow=0)
ph = PasswordHasher()

@app.get("/")
def home():
    return render_template("index.html")
    
@app.get("/profile")
@login_required
def profile():
    return {"email": session["email"], "role": session["role"]}


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

    # POST
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    if not email or not password:
        return {"ok": False, "error": "missing email or password"}, 400

    pwd_hash = ph.hash(password)

    try:
        with engine.begin() as conn:
            user_id = conn.execute(
                text("""
                    INSERT INTO users (email, password_hash)
                    VALUES (:email, :password_hash)
                    ON CONFLICT (email) DO NOTHING
                    RETURNING id
                """),
                {"email": email, "password_hash": pwd_hash},
            ).scalar()

            if not user_id:
                return {"ok": False, "error": "email already exists"}, 400

            # ha használod a verifikációt:
            token = make_verify_token()
            expires = datetime.now(timezone.utc) + timedelta(hours=24)
            conn.execute(
                text("INSERT INTO verify_tokens (user_id, token, expires_at) VALUES (:u,:t,:e)"),
                {"u": user_id, "t": token, "e": expires},
            )
        send_verification_email(email, token)
    except IntegrityError:
        return {"ok": False, "error": "email already exists"}, 400

    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    if not email or not password:
        return {"ok": False, "error": "missing email or password"}, 400

    # user lekérés (hozzuk az is_verified-et is)
    with engine.connect() as conn:
        row = conn.execute(
            text("""
                SELECT id, password_hash, role, is_verified
                FROM users
                WHERE email = :email
                LIMIT 1
            """),
            {"email": email}
        ).mappings().first()

    if not row:
        return {"ok": False, "error": "invalid credentials"}, 401

    try:
        ph.verify(row["password_hash"], password)   # ← EZ legyen a try alatt beljebb húzva
    except VerifyMismatchError:
        return {"ok": False, "error": "invalid credentials"}, 401

    if not row["is_verified"]:
        return {"ok": False, "error": "email not verified"}, 403

    # OK → session
    session["user_id"] = row["id"]
    session["email"] = email
    session["role"] = row["role"]
    return redirect(url_for("home"))
    

@app.get("/verify")
def verify():
    token = (request.args.get("token") or "").strip()
    if not token:
        return {"ok": False, "error": "missing token"}, 400

    now = datetime.now(timezone.utc)
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT user_id, expires_at FROM verify_tokens WHERE token = :t LIMIT 1"),
            {"t": token}
        ).mappings().first()

        if not row:
            return {"ok": False, "error": "invalid token"}, 400
        if row["expires_at"] < now:
            conn.execute(text("DELETE FROM verify_tokens WHERE token = :t"), {"t": token})
            return {"ok": False, "error": "token expired"}, 400

        # aktiválás + token törlés
        conn.execute(text("UPDATE users SET is_verified = true WHERE id = :uid"), {"uid": row["user_id"]})
        conn.execute(text("DELETE FROM verify_tokens WHERE token = :t"), {"t": token})

    return redirect(url_for("login"))



@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))
