"""
Secure File Suite — web application for Render and localhost.

Run locally:  python app.py  →  http://127.0.0.1:5000/
Production:   gunicorn app:app --bind 0.0.0.0:$PORT
"""

import os
import secrets
import string

from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.utils import secure_filename

import auth
import decryption
import encryption
import hashing
import integrity_checker
import steganography

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
ENCRYPTED_DIR = os.path.join(BASE_DIR, "encrypted")
DECRYPTED_DIR = os.path.join(BASE_DIR, "decrypted")
HIDDEN_DIR = os.path.join(BASE_DIR, "hidden_images")

ALLOWED_DOWNLOAD = {
    "encrypted": ENCRYPTED_DIR,
    "decrypted": DECRYPTED_DIR,
    "hidden": HIDDEN_DIR,
}

for folder in (UPLOAD_DIR, ENCRYPTED_DIR, DECRYPTED_DIR, HIDDEN_DIR):
    os.makedirs(folder, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "securefile-dev-secret-change-in-production")
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024


def _save_upload(field: str) -> str | None:
    file = request.files.get(field)
    if not file or not file.filename:
        return None
    name = secure_filename(file.filename)
    path = os.path.join(UPLOAD_DIR, name)
    file.save(path)
    return path


def _login_required():
    if not session.get("user"):
        flash("Please log in to use the tools.", "error")
        return False
    return True


def _go(panel: str, download: tuple[str, str] | None = None):
    url = url_for("index")
    if download:
        folder, name = download
        url = url_for("index", dl=folder, file=name)
    return redirect(f"{url}#{panel}")


@app.get("/")
def index():
    return render_template("index.html", user=session.get("user"))


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/login")
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    result = auth.login(username, password)
    if result["success"]:
        session["user"] = username
        flash(result["message"], "success")
    else:
        flash(result["message"], "error")
    return redirect(url_for("index"))


@app.post("/register")
def register():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    result = auth.register(username, password)
    flash(result["message"], "success" if result["success"] else "error")
    if result["success"]:
        return redirect(url_for("index"))
    return redirect(url_for("index", auth="register"))


@app.get("/logout")
def logout():
    session.pop("user", None)
    flash("Logged out.", "success")
    return redirect(url_for("index"))


@app.post("/encrypt")
def encrypt():
    if not _login_required():
        return redirect(url_for("index"))
    path = _save_upload("file")
    password = request.form.get("password", "")
    if not path or not password:
        flash("File and password are required.", "error")
        return _go("encrypt")
    base = os.path.splitext(secure_filename(request.files["file"].filename))[0]
    out = os.path.join(ENCRYPTED_DIR, f"{base}.enc")
    result = encryption.encrypt_file(path, out, password)
    if result["success"]:
        flash(result["message"], "success")
        flash(f"SHA-256 (ciphertext): {result.get('hash', '')}", "info")
        return _go("encrypt", ("encrypted", f"{base}.enc"))
    flash(result["message"], "error")
    return _go("encrypt")


@app.post("/decrypt")
def decrypt_route():
    if not _login_required():
        return redirect(url_for("index"))
    path = _save_upload("file")
    password = request.form.get("password", "")
    if not path or not password:
        flash("File and password are required.", "error")
        return _go("decrypt")
    name = secure_filename(request.files["file"].filename)
    if name.endswith(".enc"):
        name = name[:-4]
    out = os.path.join(DECRYPTED_DIR, name or "decrypted_output")
    result = decryption.decrypt_file(path, out, password)
    if result["success"]:
        flash(result["message"], "success")
        return _go("decrypt", ("decrypted", os.path.basename(out)))
    flash(result["message"], "error")
    return _go("decrypt")


@app.post("/hash")
def hash_route():
    if not _login_required():
        return redirect(url_for("index"))
    algorithm = request.form.get("algorithm", "sha256")
    text = request.form.get("text", "").strip()
    if text:
        result = hashing.hash_text(text, algorithm)
    else:
        path = _save_upload("file")
        if not path:
            flash("Provide text or upload a file.", "error")
            return _go("hash")
        result = hashing.hash_file(path, algorithm)
    if result["success"]:
        flash(f"{result['algorithm'].upper()}: {result['hash']}", "success")
    else:
        flash(result.get("message", "Hash failed."), "error")
    return _go("hash")


@app.post("/stego-hide")
def stego_hide():
    if not _login_required():
        return redirect(url_for("index"))
    path = _save_upload("image")
    message = request.form.get("message", "")
    if not path or not message:
        flash("Image and message are required.", "error")
        return _go("stego")
    base = os.path.splitext(secure_filename(request.files["image"].filename))[0]
    out = os.path.join(HIDDEN_DIR, f"{base}_hidden.png")
    result = steganography.hide_message(path, message, out)
    if result["success"]:
        flash(result["message"], "success")
        return _go("stego", ("hidden", f"{base}_hidden.png"))
    flash(result["message"], "error")
    return _go("stego")


@app.post("/stego-extract")
def stego_extract():
    if not _login_required():
        return redirect(url_for("index"))
    path = _save_upload("image")
    if not path:
        flash("Upload an image.", "error")
        return _go("stego")
    result = steganography.extract_message(path)
    if result["success"]:
        flash(f"Hidden message: {result['hidden_text']}", "success")
    else:
        flash(result["message"], "error")
    return _go("stego")


@app.post("/integrity-baseline")
def integrity_baseline():
    if not _login_required():
        return redirect(url_for("index"))
    path = _save_upload("file")
    if not path:
        flash("Upload a file.", "error")
        return _go("integrity")
    result = integrity_checker.save_baseline(path)
    flash(result["message"] + (f" Hash: {result['hash']}" if result.get("hash") else ""), "success" if result["success"] else "error")
    return _go("integrity")


@app.post("/integrity-verify")
def integrity_verify():
    if not _login_required():
        return redirect(url_for("index"))
    path = _save_upload("file")
    if not path:
        flash("Upload a file.", "error")
        return _go("integrity")
    result = integrity_checker.verify_integrity(path)
    level = "success" if result.get("is_intact") else "error" if result.get("is_intact") is False else "error"
    flash(result["message"], level)
    return _go("integrity")


@app.post("/generate-password")
def generate_password():
    if not _login_required():
        return redirect(url_for("index"))
    try:
        length = max(8, min(128, int(request.form.get("length", 16))))
    except ValueError:
        length = 16
    chars = ""
    if request.form.get("upper"):
        chars += string.ascii_uppercase
    if request.form.get("lower"):
        chars += string.ascii_lowercase
    if request.form.get("digits"):
        chars += string.digits
    if request.form.get("symbols"):
        chars += string.punctuation
    if not chars:
        flash("Select at least one character type.", "error")
        return _go("password")
    password = "".join(secrets.choice(chars) for _ in range(length))
    flash(f"Generated password ({length} chars): {password}", "success")
    return _go("password")


@app.get("/download/<folder>/<path:filename>")
def download(folder, filename):
    if not _login_required():
        return redirect(url_for("index"))
    base = ALLOWED_DOWNLOAD.get(folder)
    if not base:
        flash("Invalid download.", "error")
        return redirect(url_for("index"))
    safe = secure_filename(filename)
    path = os.path.join(base, safe)
    if not os.path.isfile(path):
        flash("File not found.", "error")
        return redirect(url_for("index"))
    return send_from_directory(base, safe, as_attachment=True)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "127.0.0.1")
    print(f"Secure File Suite: http://{host}:{port}/")
    app.run(host=host, port=port, debug=os.environ.get("FLASK_DEBUG", "1") == "1")
