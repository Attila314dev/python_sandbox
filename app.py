import os, sys, secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.middleware.proxy_fix import ProxyFix

from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

import requests


# -----------------------------
# Flask app & config
# -----------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-only-change-me")
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=3600,  # 1 óra
)
# Render/Proxy mögött helyes host/scheme
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config["PREFERRED_URL_SCHEME"] = "https"

# -----------------------------
# Database (Neon / psycopg3)
# -----------------------------
DATABASE_URL = os.getenv("DATABASE_URL", "")
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=2,
    max_overflow=0,
)
ph = PasswordHasher()


# -----------------------------
# Helpers
# -----------------------------
def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


def make_verify_token() -> str:
    return secrets.token_urlsafe(32)


def send_verification_email(to_email: str, link: str) -> None:
    """Send verification link via Resend."""
    api_key = os.getenv("RESEND_API_KEY")
    from_email = os.getenv("FROM_EMAIL", "no-reply@resend.dev")
    payload = {
        "from": f"My Tutorial <{from_email}>",
        "to": [to_email],
        "subject": "Verify your email",
        "html": f'<p>Click to verify your account:</p><p><a href="{link}">{link}</a></p>',
    }
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    try:
        r = requests.post("https://api.resend.com/emails", json=payload, headers=headers, timeout=10)
        if r.status_code >= 300:
            print(f"[Resend verify] {r.status_code} {r.text}", file=sys.stderr)
    except Exception as e:
        print(f"[Resend verify EXC] {e}", file=sys.stderr)
    # dev log
    print(f"[DEV] Verify link for {to_email}: {link}", file=sys.stderr)


def make_mfa_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"  # 000000..999999


def send_mfa_email(to_email: str, code: str) -> None:
    """Send MFA code via Resend."""
    api_key = os.getenv("RESEND_API_KEY")
    from_email = os.getenv("FROM_EMAIL", "no-reply@resend.dev")
    payload = {
        "from": f"My Tutorial <{from_email}>",
        "to": [to_email],
        "subject": "Your login code",
        "html": f"<p>Your code is: <b>{code}</b></p><p>It expires in 10 minutes.</p>",
    }
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    try:
        r = requests.post("https://api.resend.com/emails", json=payload, headers=headers, timeout=10)
        if r.status_code >= 300:
            print(f"[Resend MFA] {r.status_code} {r.text}", file=sys.stderr)
    except Exception as e:
        print(f"[Resend MFA EXC] {e}", file=sys.stderr)
    # dev log
    print(f"[DEV] MFA code for {to_email}: {code}", file=sys.stderr)


# -----------------------------
# Routes
# -----------------------------
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
            # user insert
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

            # verification token (24h)
            token = make_verify_token()
            expires = datetime.now(timezone.utc) + timedelta(hours=24)
            conn.execute(
                text("INSERT INTO verify_tokens (user_id, token, expires_at) VALUES (:u,:t,:e)"),
                {"u": user_id, "t": token, "e": expires},
            )

        # build link from real host
        verify_link = url_for("verify", token=token, _external=True)
        send_verification_email(email, verify_link)

    except IntegrityError:
        return {"ok": False, "error": "email already exists"}, 400
    except Exception as e:
        print(f"[register EXC] {e}", file=sys.stderr)
        return {"ok": False, "error": "db error"}, 400

    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    if not email or not password:
        return {"ok": False, "error": "missing email or password"}, 400

    # user lekérés (is_verified-del együtt)
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

    # jelszó ellenőrzés
    try:
        ph.verify(row["password_hash"], password)
    except VerifyMismatchError:
        return {"ok": False, "error": "invalid credentials"}, 401

    # kötelező email-verifikáció
    if not row["is_verified"]:
        return {"ok": False, "error": "email not verified"}, 403

    # MFA: 6 jegyű kód (10 perc)
    code = make_mfa_code()
    expires = datetime.now(timezone.utc) + timedelta(minutes=10)
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM mfa_codes WHERE user_id = :u"), {"u": row["id"]})
        conn.execute(
            text("INSERT INTO mfa_codes (user_id, code, expires_at) VALUES (:u, :c, :e)"),
            {"u": row["id"], "c": code, "e": expires},
        )

    send_mfa_email(email, code)

    # fél-login state
    session.clear()
    session["mfa_user_id"] = row["id"]
    session["mfa_email"] = email
    session["mfa_role"] = row["role"]

    return redirect(url_for("mfa"))


@app.route("/mfa", methods=["GET", "POST"])
def mfa():
    # kell pending MFA state
    if "mfa_user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "GET":
        return render_template("mfa.html")

    code = (request.form.get("code") or "").strip()
    if not code:
        return {"ok": False, "error": "missing code"}, 400

    now = datetime.now(timezone.utc)
    with engine.begin() as conn:
        row = conn.execute(
            text("""
                SELECT id, expires_at
                FROM mfa_codes
                WHERE user_id = :u AND code = :c
                ORDER BY created_at DESC
                LIMIT 1
            """),
            {"u": session["mfa_user_id"], "c": code},
        ).mappings().first()

        if not row:
            return {"ok": False, "error": "invalid code"}, 401
        if row["expires_at"] < now:
            conn.execute(text("DELETE FROM mfa_codes WHERE id = :id"), {"id": row["id"]})
            return {"ok": False, "error": "code expired"}, 401

        # OK → takarítás
        conn.execute(text("DELETE FROM mfa_codes WHERE user_id = :u"), {"u": session["mfa_user_id"]})

    # finalize login
    session["user_id"] = session.pop("mfa_user_id")
    session["email"] = session.pop("mfa_email")
    session["role"] = session.pop("mfa_role")

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
