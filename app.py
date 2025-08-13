import os
from flask import Flask, render_template
from sqlalchemy import create_engine, text

app = Flask(__name__)

# DB engine létrehozása env-ből
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)

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
