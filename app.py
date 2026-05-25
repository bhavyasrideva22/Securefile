"""
Minimal WSGI entry point for Render (and similar hosts).

The desktop GUI lives in main.py; this module only exposes a health check
so the web service can bind to PORT and pass deploy health checks.
"""

from flask import Flask, jsonify

app = Flask(__name__)


@app.get("/")
def index():
    return jsonify(
        {
            "status": "ok",
            "message": "Secure File Suite API is running. Use main.py locally for the GUI.",
        }
    )


@app.get("/health")
def health():
    return jsonify({"status": "ok"})
