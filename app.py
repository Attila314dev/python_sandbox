from flask import request, redirect, url_for
from argon2 import PasswordHasher
from sqlalchemy import text

ph = PasswordHasher()

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    # POST
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""

    if not email or not password:
        return {"ok": False, "error": "missing email or password"}, 400

    # jelszó hash
    pwd_hash = ph.hash(password)

    # beszúrás (duplikált email kezelése)
    try:
        with engine.begin() as conn:
            conn.execute(
                text("""
                    INSERT INTO users (email, password_hash)
                    VALUES (:email, :password_hash)
                """),
                {"email": email, "password_hash": pwd_hash},
            )
    except Exception as e:
        # ha már létezik az email (unique constraint), ide esünk
        return {"ok": False, "error": "email already exists or db error"}, 400

    return redirect(url_for("home"))
