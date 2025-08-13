from flask import Flask, render_template
app = Flask(__name__)

@app.get("/")
def home():
    return render_template("index.html")

@app.get("/health")
def health():
    return {"ok": True}
