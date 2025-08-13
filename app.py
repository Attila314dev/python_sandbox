import os
from flask import Flask, render_template
from sqlalchemy import create_engine, text

app = Flask(__name__)

DATABASE_URL = os.getenv("DATABASE_URL")
# ↳ psycopg3 driverre váltunk (külön csomag telepítés nélkül)
if DATABASE_URL and DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

# kis pool, hogy ne fogyjon el a free connection limit
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=2,
    max_overflow=0,
)

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
