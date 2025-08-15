import os, sys, secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.middleware.proxy_fix import ProxyFix

from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

import requests
import urllib.parse

def _db_info_from_url(db_url: str):
    try:
        p = urllib.parse.urlparse(db_url)
        host = p.hostname or "-"
        db   = (p.path or "/").lstrip("/") or "-"
        return host, db
    except Exception:
        return "-", "-"

def build_status():
    # Render WS
    app_url = (os.getenv("APP_BASE_URL") or request.url_root).rstrip("/")
    ws_ok = True
    try:
        r = requests.get(f"{app_url}/health", timeout=3)
        ws_ok = (r.status_code == 200 and (r.json().get("ok") is True))
    except Exception:
        ws_ok = False

    # GitHub
    gh_url = os.getenv("GITHUB_REPO_URL")

    # Resend (nagyon egyszerű “él-e az API kulcs” próba)
    resend_key = os.getenv("RESEND_API_KEY")
    resend_status = {"label": "Not configured", "kind": "warn"}
    if resend_key:
        try:
            rr = requests.get(
                "https://api.resend.com/domains",
                headers={"Authorization": f"Bearer {resend_key}"},
                timeout=5,
            )
            if 200 <= rr.status_code < 300:
                # Nem bontjuk ki a domain listát most; a lényeg, hogy az API él
                resend_status = {"label": "API OK (domain verify ajánlott)", "kind": "ok"}
            elif rr.status_code in (401, 403):
                resend_status = {"label": "API key / sandbox limit (verify domain kell)", "kind": "warn"}
            else:
                resend_status = {"label": f"API error {rr.status_code}", "kind": "err"}
        except Exception:
            resend_status = {"label": "API unreachable", "kind": "err"}

    # Neon DB
    db_ok = True
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        db_ok = False
    host, dbname = _db_info_from_url(DATABASE_URL)

    # Domain/DNS
    domain_name = os.getenv("DOMAIN_NAME") or "—"
    dns_provider = os.getenv("DNS_PROVIDER") or "—"

    return {
        "render": {
            "up": ws_ok,
            "url": app_url,
            "commit": os.getenv("RENDER_GIT_COMMIT") or os.getenv("GIT_COMMIT"),
        },
        "github": {"url": gh_url},
        "resend": resend_status,
        "neon": {"ok": db_ok, "host": host, "db": dbname},
        "domain": {"name": domain_name, "dns": dns_provider},
    }

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
# Render/Proxy mögött helyes host/scheme + kliens IP
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
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

def client_ip() -> str:
    # ProxyFix után az access_route[-1] lesz a kliens
    if request.access_route:
        return request.access_route[-1]
    return request.remote_addr or "0.0.0.0"

def log_attempt(ip: str, email: str | None, kind: str, success: bool) -> None:
    with engine.begin() as conn:
        conn.execute(
            text("INSERT INTO auth_attempts (ip, email, kind, success) VALUES (:ip,:em,:k,:s)"),
            {"ip": ip, "em": email, "k": kind, "s": success},
        )

def too_many_failures(ip: str, kind: str, minutes: int, limit: int) -> bool:
    window_start = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    with engine.connect() as conn:
        n = conn.execute(
            text("""SELECT COUNT(*) FROM auth_attempts
                    WHERE ip=:ip AND kind=:k AND success=false AND ts > :ws"""),
            {"ip": ip, "k": kind, "ws": window_start},
        ).scalar()
    return (n or 0) >= limit

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
    print(f"[DEV] Verify link for {to_email}: {link}", file=sys.stderr)

def make_mfa_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"

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
    print(f"[DEV] MFA code for {to_email}: {code}", file=sys.stderr)

# -----------------------------
# Routes
# -----------------------------
@app.get("/")
def home():
    return render_template("index.html", status=build_status())

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
    password2 = request.form.get("password2") or ""
    if not email or not password:
        flash("Hiányzó email vagy jelszó.", "error")
        return render_template("register.html"), 400
    if password != password2:
        flash("A két jelszó nem egyezik.", "error")
        return render_template("register.html"), 400

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
                flash("Ez az email már használatban van.", "error")
                return render_template("register.html"), 400

            token = make_verify_token()
            expires = datetime.now(timezone.utc) + timedelta(hours=24)
            conn.execute(
                text("INSERT INTO verify_tokens (user_id, token, expires_at) VALUES (:u,:t,:e)"),
                {"u": user_id, "t": token, "e": expires},
            )

        verify_link = url_for("verify", token=token, _external=True)
        send_verification_email(email, verify_link)
        flash("Verifikációs link elküldve az email címedre.", "success")

    except IntegrityError:
        flash("Ez az email már használatban van.", "error")
        return render_template("register.html"), 400
    except Exception as e:
        print(f"[register EXC] {e}", file=sys.stderr)
        flash("Adatbázis hiba.", "error")
        return render_template("register.html"), 400

    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    ip = client_ip()
    if too_many_failures(ip, "login", minutes=1, limit=5):
        flash("Túl sok próbálkozás. Próbáld újra hamarosan.", "error")
        return redirect(url_for("login"))

    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    if not email or not password:
        log_attempt(ip, email, "login", False)
        flash("Hiányzó email vagy jelszó.", "error")
        return redirect(url_for("login"))

    # user + is_verified
    with engine.connect() as conn:
        row = conn.execute(
            text("""SELECT id, password_hash, role, is_verified
                    FROM users WHERE email = :email LIMIT 1"""),
            {"email": email}
        ).mappings().first()

    if not row:
        log_attempt(ip, email, "login", False)
        flash("Hibás email vagy jelszó.", "error")
        return redirect(url_for("login"))

    try:
        ph.verify(row["password_hash"], password)
    except VerifyMismatchError:
        log_attempt(ip, email, "login", False)
        flash("Hibás email vagy jelszó.", "error")
        return redirect(url_for("login"))

    if not row["is_verified"]:
        log_attempt(ip, email, "login", False)
        flash("Előbb erősítsd meg az email címedet.", "error")
        return redirect(url_for("login"))

    # MFA kód (10 perc)
    code = make_mfa_code()
    expires = datetime.now(timezone.utc) + timedelta(minutes=10)
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM mfa_codes WHERE user_id = :u"), {"u": row["id"]})
        conn.execute(
            text("INSERT INTO mfa_codes (user_id, code, expires_at) VALUES (:u,:c,:e)"),
            {"u": row["id"], "c": code, "e": expires},
        )
    send_mfa_email(email, code)
    flash("Belépési kódot küldtünk emailben.", "success")

    # fél-login state
    session.clear()
    session["mfa_user_id"] = row["id"]
    session["mfa_email"] = email
    session["mfa_role"] = row["role"]

    log_attempt(ip, email, "login", True)
    return redirect(url_for("mfa"))

@app.route("/mfa", methods=["GET", "POST"])
def mfa():
    if "mfa_user_id" not in session:
        return redirect(url_for("login"))

    ip = client_ip()
    if request.method == "GET":
        return render_template("mfa.html")

    if too_many_failures(ip, "mfa", minutes=10, limit=5):
        flash("Túl sok hibás kód. Próbáld később.", "error")
        return redirect(url_for("mfa"))

    code = (request.form.get("code") or "").strip()
    if not code:
        log_attempt(ip, session.get("mfa_email"), "mfa", False)
        flash("Hiányzik a kód.", "error")
        return redirect(url_for("mfa"))

    now = datetime.now(timezone.utc)
    with engine.begin() as conn:
        row = conn.execute(
            text("""SELECT id, expires_at FROM mfa_codes
                    WHERE user_id = :u AND code = :c
                    ORDER BY created_at DESC LIMIT 1"""),
            {"u": session["mfa_user_id"], "c": code},
        ).mappings().first()

        if not row:
            log_attempt(ip, session.get("mfa_email"), "mfa", False)
            flash("Érvénytelen kód.", "error")
            return redirect(url_for("mfa"))
        if row["expires_at"] < now:
            conn.execute(text("DELETE FROM mfa_codes WHERE id = :id"), {"id": row["id"]})
            log_attempt(ip, session.get("mfa_email"), "mfa", False)
            flash("A kód lejárt.", "error")
            return redirect(url_for("mfa"))

        # OK → takarítás
        conn.execute(text("DELETE FROM mfa_codes WHERE user_id = :u"), {"u": session["mfa_user_id"]})

    # finalize login
    session["user_id"] = session.pop("mfa_user_id")
    session["email"]   = session.pop("mfa_email")
    session["role"]    = session.pop("mfa_role")

    log_attempt(ip, session["email"], "mfa", True)
    flash("Sikeres bejelentkezés.", "success")
    return redirect(url_for("home"))

@app.route("/resend-verification", methods=["GET", "POST"])
def resend_verification():
    if request.method == "GET":
        return render_template("resend.html")

    ip = client_ip()
    email = (request.form.get("email") or "").strip().lower()

    # rate limit: max 3/óra / email + IP
    window = datetime.now(timezone.utc) - timedelta(hours=1)
    with engine.connect() as conn:
        cnt = conn.execute(
            text("""SELECT COUNT(*) FROM auth_attempts
                    WHERE kind='resend' AND ts > :ws AND (email=:em OR ip=:ip)"""),
            {"ws": window, "em": email, "ip": ip},
        ).scalar()
    if (cnt or 0) >= 3:
        flash("Túl sok kérés. Próbáld később.", "error")
        return redirect(url_for("resend_verification"))

    sent = False
    try:
        with engine.begin() as conn:
            u = conn.execute(
                text("SELECT id, is_verified FROM users WHERE email=:em LIMIT 1"),
                {"em": email},
            ).mappings().first()

            if u and not u["is_verified"]:
                token = make_verify_token()
                expires = datetime.now(timezone.utc) + timedelta(hours=24)
                conn.execute(text("DELETE FROM verify_tokens WHERE user_id = :u"),
                             {"u": u["id"]})
                conn.execute(
                    text("INSERT INTO verify_tokens (user_id, token, expires_at) VALUES (:u,:t,:e)"),
                    {"u": u["id"], "t": token, "e": expires},
                )
                link = url_for("verify", token=token, _external=True)
                send_verification_email(email, link)
                sent = True
    finally:
        # pontos log: csak akkor success, ha tényleg küldtünk
        log_attempt(ip, email, "resend", sent)
        # dev log, hogy tudd miért nem ment ki
        print(f"[DEV] resend: exists={bool(u) if 'u' in locals() else None}, "
              f"verified={None if not u else u['is_verified']}, sent={sent}",
              file=sys.stderr)

    # a felhasználónak mindig általános válasz (privacy)
    flash("Ha létezik és nincs megerősítve az email, új linket küldtünk.", "success")
    return redirect(url_for("login"))

@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "GET":
        return render_template("change_password.html")

    cur = request.form.get("current") or ""
    new = request.form.get("new") or ""
    new2 = request.form.get("new2") or ""

    if len(new) < 8:
        flash("Az új jelszó túl rövid (min. 8).", "error")
        return render_template("change_password.html"), 400
    if new != new2:
        flash("A két új jelszó nem egyezik.", "error")
        return render_template("change_password.html"), 400

    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT password_hash FROM users WHERE id=:id"),
            {"id": session["user_id"]},
        ).mappings().first()

    try:
        ph.verify(row["password_hash"], cur)
    except Exception:
        flash("A jelenlegi jelszó nem megfelelő.", "error")
        return render_template("change_password.html"), 401

    new_hash = ph.hash(new)
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE users SET password_hash=:h WHERE id=:id"),
            {"h": new_hash, "id": session["user_id"]},
        )
        conn.execute(text("DELETE FROM mfa_codes WHERE user_id = :u"),
                     {"u": session["user_id"]})

    flash("Jelszó frissítve.", "success")
    return redirect(url_for("profile"))

@app.get("/verify")
def verify():
    token = (request.args.get("token") or "").strip()
    if not token:
        flash("Hiányzó token.", "error")
        return redirect(url_for("login"))

    now = datetime.now(timezone.utc)
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT user_id, expires_at FROM verify_tokens WHERE token = :t LIMIT 1"),
            {"t": token}
        ).mappings().first()

        if not row:
            flash("Érvénytelen verifikációs link.", "error")
            return redirect(url_for("login"))
        if row["expires_at"] < now:
            conn.execute(text("DELETE FROM verify_tokens WHERE token = :t"), {"t": token})
            flash("A verifikációs link lejárt.", "error")
            return redirect(url_for("login"))

        conn.execute(text("UPDATE users SET is_verified = true WHERE id = :uid"), {"uid": row["user_id"]})
        conn.execute(text("DELETE FROM verify_tokens WHERE token = :t"), {"t": token})

    flash("Email megerősítve. Most már bejelentkezhetsz.", "success")
    return redirect(url_for("login"))

@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))
