import argparse
import base64
import datetime
import hashlib
import io
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import uuid
from functools import wraps
from crypto_utils import (new_data_key, encrypt_bytes, decrypt_bytes,
                          load_master_key, sha256_hex, load_signing_key,
                          sign_file_record, verify_file_record)

import bcrypt
from Crypto.Cipher import AES
from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, g, send_file, abort)
import lab_core

from crypto_utils import (new_data_key, encrypt_bytes, decrypt_bytes,
                          load_master_key, sha256_hex)

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
STORAGE = os.path.join(DATA, "storage")
os.makedirs(STORAGE, exist_ok=True)
DB_PATH = os.path.join(DATA, "securedrive.db")

ALLOWED_EXT = {"txt", "pdf", "jpg", "jpeg", "png", "mp3", "mp4"}
MAX_MB = 100
MAX_FAILS = 5          # failed logins before lockout
LOCK_SECONDS = 60      # how long the account stays locked


def load_secret_key():
    """Random key used to sign session cookies. Created once, then reused."""
    path = os.path.join(DATA, "session.key")
    if not os.path.exists(path):
        with open(path, "wb") as f:
            f.write(os.urandom(32))
    with open(path, "rb") as f:
        return f.read()


app = Flask(__name__)
app.config["SECRET_KEY"] = load_secret_key()
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["MAX_CONTENT_LENGTH"] = (MAX_MB + 5) * 1024 * 1024

MASTER_KEY = load_master_key(os.path.join(DATA, "master.key"))
SIGN_KEY = load_signing_key(os.path.join(DATA, "signing.key"))
VERIFY_KEY = SIGN_KEY.public_key()


# ---------- database ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=10)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        pw_hash BLOB NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP)""")
    con.execute("""CREATE TABLE IF NOT EXISTS files(
        id TEXT PRIMARY KEY,
        owner_id INTEGER NOT NULL,
        orig_name TEXT NOT NULL,
        size INTEGER,
        wrapped_key BLOB NOT NULL,
        uploaded_at TEXT DEFAULT CURRENT_TIMESTAMP)""")
    cols = [r[1] for r in con.execute("PRAGMA table_info(files)")]
    if "sha256" not in cols:
        con.execute("ALTER TABLE files ADD COLUMN sha256 TEXT")
    for col, typ in (("signature", "TEXT"), ("enc_ms", "REAL"), ("sign_ms", "REAL")):
        if col not in cols:
            con.execute(f"ALTER TABLE files ADD COLUMN {col} {typ}")
    ucols = [r[1] for r in con.execute("PRAGMA table_info(users)")]
    if "failed_logins" not in ucols:
        con.execute("ALTER TABLE users ADD COLUMN failed_logins INTEGER DEFAULT 0")
    if "locked_until" not in ucols:
        con.execute("ALTER TABLE users ADD COLUMN locked_until REAL DEFAULT 0")
    con.execute("""CREATE TABLE IF NOT EXISTS shares(
        file_id TEXT, user_id INTEGER,
        PRIMARY KEY(file_id, user_id))""")
    con.execute("""CREATE TABLE IF NOT EXISTS audit(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT, username TEXT, action TEXT, filename TEXT,
        ip TEXT, status TEXT, detail TEXT,
        prev_hash TEXT, entry_hash TEXT)""")
    con.commit()
    con.close()


init_db()


# ---------- helpers ----------
def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "uid" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


@app.before_request
def csrf_protect():
    """Give every session a secret token; every POST must send it back."""
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    if request.method == "POST":
        sent = request.form.get("csrf", "")
        if not secrets.compare_digest(sent, session["csrf"]):
            abort(400, "Invalid or missing CSRF token.")


@app.context_processor
def inject_csrf():
    return {"csrf_token": session.get("csrf", "")}


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"   # no MIME guessing
    resp.headers["X-Frame-Options"] = "DENY"             # cannot be put in an iframe
    resp.headers["Cache-Control"] = "no-store"           # do not cache private pages
    return resp


def get_accessible_file(file_id):
    """Return the file row if the logged-in user owns it OR it was shared with them."""
    return get_db().execute(
        "SELECT f.* FROM files f WHERE f.id = ? AND (f.owner_id = ? OR EXISTS "
        "(SELECT 1 FROM shares s WHERE s.file_id = f.id AND s.user_id = ?))",
        (file_id, session["uid"], session["uid"])).fetchone()


audit_lock = threading.Lock()


def _entry_hash(prev, ts, user, action, fname, ip, status, detail):
    fields = [prev, ts, user or "", action, fname or "", ip or "", status, detail or ""]
    return hashlib.sha256(json.dumps(fields).encode()).hexdigest()


def log_event(action, filename=None, status="SUCCESS", detail="", username=None):
    """Append one entry to the audit log, chained to the previous entry."""
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user = username or session.get("username")
    ip = request.remote_addr
    with audit_lock:                      # one writer at a time keeps the chain in order
        db = get_db()
        last = db.execute(
            "SELECT entry_hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        prev = last["entry_hash"] if last else "GENESIS"
        h = _entry_hash(prev, ts, user, action, filename, ip, status, detail)
        db.execute(
            "INSERT INTO audit(ts, username, action, filename, ip, status, detail, "
            "prev_hash, entry_hash) VALUES(?,?,?,?,?,?,?,?,?)",
            (ts, user, action, filename, ip, status, detail, prev, h))
        db.commit()


def verify_audit_chain():
    """Re-compute every hash. Returns (True, None) or (False, id_of_first_bad_row)."""
    prev = "GENESIS"
    for r in get_db().execute("SELECT * FROM audit ORDER BY id"):
        expected = _entry_hash(prev, r["ts"], r["username"], r["action"],
                               r["filename"], r["ip"], r["status"], r["detail"])
        if r["prev_hash"] != prev or r["entry_hash"] != expected:
            return False, r["id"]
        prev = r["entry_hash"]
    return True, None


# ---------- routes ----------
@app.route("/")
@login_required
def home():
    db = get_db()
    files = db.execute(
        "SELECT * FROM files WHERE owner_id = ? ORDER BY uploaded_at DESC",
        (session["uid"],)).fetchall()
    shared = db.execute(
        "SELECT f.*, o.username AS owner FROM files f "
        "JOIN shares s ON s.file_id = f.id "
        "JOIN users o ON o.id = f.owner_id "
        "WHERE s.user_id = ? ORDER BY f.uploaded_at DESC",
        (session["uid"],)).fetchall()
    return render_template("home.html", username=session["username"],
                           files=files, shared=shared, max_mb=MAX_MB,
                           exts=", ".join(sorted(ALLOWED_EXT)))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not re.fullmatch(r"[A-Za-z0-9_]{3,20}", username):
            flash("Username must be 3-20 letters, digits or underscores.")
        elif not (8 <= len(password) <= 72):
            flash("Password must be 8-72 characters.")
        else:
            pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
            try:
                db = get_db()
                db.execute("INSERT INTO users(username, pw_hash) VALUES(?, ?)",
                           (username, pw_hash))
                db.commit()
                log_event("REGISTER", username=username)
                flash("Account created. Please log in.")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That username is already taken.")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?",
                          (username,)).fetchone()
        now = time.time()

        if user and user["locked_until"] > now:          # account is locked
            log_event("LOGIN", status="BLOCKED",
                      detail="account locked", username=username)
            flash("Too many failed attempts. Try again in a minute.")
        elif user and bcrypt.checkpw(password.encode(), user["pw_hash"]):
            db.execute("UPDATE users SET failed_logins = 0 WHERE id = ?", (user["id"],))
            db.commit()
            session.clear()
            session["uid"] = user["id"]
            session["username"] = user["username"]
            log_event("LOGIN", detail=request.headers.get("User-Agent", "")[:80])
            return redirect(url_for("home"))
        else:
            if user:
                fails = user["failed_logins"] + 1
                if fails >= MAX_FAILS:                   # lock the account
                    db.execute("UPDATE users SET failed_logins = 0, locked_until = ? "
                               "WHERE id = ?", (now + LOCK_SECONDS, user["id"]))
                else:
                    db.execute("UPDATE users SET failed_logins = ? WHERE id = ?",
                               (fails, user["id"]))
                db.commit()
            log_event("LOGIN", status="FAILURE",
                      detail="bad credentials", username=username)
            flash("Invalid username or password.")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    if "uid" in session:
        log_event("LOGOUT")
    session.clear()
    return redirect(url_for("login"))


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    f = request.files.get("file")
    if not f or not f.filename:
        flash("No file selected.")
        return redirect(url_for("home"))

    name = os.path.basename(f.filename)
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext not in ALLOWED_EXT:
        log_event("FILE_UPLOAD", filename=name, status="FAILURE",
                  detail="type not allowed")
        flash(f"File type .{ext} is not allowed.")
        return redirect(url_for("home"))

    data = f.read()
    if len(data) > MAX_MB * 1024 * 1024:
        log_event("FILE_UPLOAD", filename=name, status="FAILURE",
                  detail="too large")
        flash("File too large.")
        return redirect(url_for("home"))

    file_id = uuid.uuid4().hex                       # random name used on disk
    data_key = new_data_key()                        # fresh AES-256 key for this file
    t0 = time.perf_counter()
    blob = encrypt_bytes(data_key, data, aad=file_id.encode())
    enc_ms = (time.perf_counter() - t0) * 1000
    wrapped_key = encrypt_bytes(MASTER_KEY, data_key,
                                aad=b"dek:" + file_id.encode())
    digest = sha256_hex(data)
    t0 = time.perf_counter()
    signature = sign_file_record(SIGN_KEY, file_id, digest)
    sign_ms = (time.perf_counter() - t0) * 1000

    with open(os.path.join(STORAGE, file_id + ".enc"), "wb") as out:
        out.write(blob)

    db = get_db()
    db.execute("INSERT INTO files(id, owner_id, orig_name, size, sha256, wrapped_key, "
               "signature, enc_ms, sign_ms) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
               (file_id, session["uid"], name, len(data),
                digest, wrapped_key, signature, enc_ms, sign_ms))
    db.commit()
    log_event("FILE_UPLOAD", filename=name,
              detail=f"{len(data)} bytes, encrypted in {enc_ms:.2f} ms, "
                     f"signed in {sign_ms:.3f} ms")
    flash(f"'{name}' uploaded and encrypted.")
    return redirect(url_for("home"))


@app.route("/download/<file_id>")
@login_required
def download(file_id):
    row = get_accessible_file(file_id)
    if not row:
        log_event("ACCESS_DENIED", filename=file_id, status="FAILURE",
                  detail="file not found or no permission")
        abort(404)                                   # missing OR not yours: same answer

    try:
        with open(os.path.join(STORAGE, file_id + ".enc"), "rb") as fh:
            blob = fh.read()
        data_key = decrypt_bytes(MASTER_KEY, row["wrapped_key"],
                                 aad=b"dek:" + file_id.encode())
        t0 = time.perf_counter()
        data = decrypt_bytes(data_key, blob, aad=file_id.encode())
        dec_ms = (time.perf_counter() - t0) * 1000
        if row["sha256"] and sha256_hex(data) != row["sha256"]:
            raise ValueError("fingerprint mismatch")
        t0 = time.perf_counter()
        if row["signature"] and not verify_file_record(
                VERIFY_KEY, file_id, row["sha256"], row["signature"]):
            raise ValueError("signature invalid")
        ver_ms = (time.perf_counter() - t0) * 1000
    except (ValueError, FileNotFoundError):
        log_event("FILE_DOWNLOAD", filename=row["orig_name"],
                  status="INTEGRITY_FAIL",
                  detail="authentication tag / hash verification failed")
        return render_template(
            "error.html",
            msg="File integrity compromised. The stored data was modified "
                "and has NOT been released."), 422

        log_event("FILE_DOWNLOAD", filename=row["orig_name"],
              detail=f"integrity + signature verified; decrypted in "
                     f"{dec_ms:.2f} ms, signature check {ver_ms:.3f} ms")
    return send_file(io.BytesIO(data), as_attachment=True,
                     download_name=row["orig_name"])


@app.route("/share/<file_id>", methods=["POST"])
@login_required
def share(file_id):
    db = get_db()
    row = db.execute("SELECT * FROM files WHERE id = ? AND owner_id = ?",
                     (file_id, session["uid"])).fetchone()
    if not row:                                      # only the OWNER may share
        log_event("FILE_SHARE", filename=file_id, status="FAILURE",
                  detail="not owner or not found")
        abort(404)

    target = request.form.get("target", "").strip()
    user = db.execute("SELECT * FROM users WHERE username = ?", (target,)).fetchone()
    if not user or user["id"] == session["uid"]:
        flash("Pick another registered user to share with.")
    else:
        db.execute("INSERT OR IGNORE INTO shares(file_id, user_id) VALUES(?, ?)",
                   (file_id, user["id"]))
        db.commit()
        log_event("FILE_SHARE", filename=row["orig_name"],
                  detail=f"shared with {user['username']}")
        flash(f"Shared '{row['orig_name']}' with {user['username']}.")
    return redirect(url_for("home"))


@app.route("/delete/<file_id>", methods=["POST"])
@login_required
def delete(file_id):
    db = get_db()
    row = db.execute("SELECT * FROM files WHERE id = ? AND owner_id = ?",
                     (file_id, session["uid"])).fetchone()
    if not row:                                      # only the OWNER may delete
        log_event("FILE_DELETE", filename=file_id, status="FAILURE",
                  detail="not owner or not found")
        abort(404)

    try:
        os.remove(os.path.join(STORAGE, file_id + ".enc"))
    except FileNotFoundError:
        pass
    db.execute("DELETE FROM shares WHERE file_id = ?", (file_id,))
    db.execute("DELETE FROM files WHERE id = ?", (file_id,))
    db.commit()
    log_event("FILE_DELETE", filename=row["orig_name"])
    flash(f"'{row['orig_name']}' deleted.")
    return redirect(url_for("home"))


@app.route("/audit")
@login_required
def audit():
    rows = get_db().execute(
        "SELECT * FROM audit WHERE username = ? ORDER BY id DESC LIMIT 200",
        (session["username"],)).fetchall()
    ok, bad_id = verify_audit_chain()
    return render_template("audit.html", rows=rows, chain_ok=ok, bad_id=bad_id)


@app.errorhandler(413)
def too_large(e):
    return f"Upload exceeds the {MAX_MB} MB limit.", 413


def ensure_cert():
    """Create the certificate the first time HTTPS is used."""
    cert = os.path.join(BASE, "certs", "cert.pem")
    key = os.path.join(BASE, "certs", "key.pem")
    if not (os.path.exists(cert) and os.path.exists(key)):
        os.makedirs(os.path.join(BASE, "certs"), exist_ok=True)
        from gen_cert import generate
        generate(cert, key)
    return cert, key

# ---------- crypto lab pages (ISL project) ----------
IMG_MIME = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg"}


@app.route("/inspect/<file_id>")
@login_required
def inspect_file(file_id):
    """Show the plaintext and the ciphertext of one stored file, with the lab numbers."""
    row = get_accessible_file(file_id)
    if not row:
        log_event("ACCESS_DENIED", filename=file_id, status="FAILURE",
                  detail="inspect: file not found or no permission")
        abort(404)
    try:
        with open(os.path.join(STORAGE, file_id + ".enc"), "rb") as fh:
            blob = fh.read()
        data_key = decrypt_bytes(MASTER_KEY, row["wrapped_key"],
                                 aad=b"dek:" + file_id.encode())
        t0 = time.perf_counter()
        plain = decrypt_bytes(data_key, blob, aad=file_id.encode())
        dec_ms = (time.perf_counter() - t0) * 1000
    except (ValueError, FileNotFoundError):
        log_event("FILE_INSPECT", filename=row["orig_name"], status="INTEGRITY_FAIL",
                  detail="decryption failed")
        return render_template("error.html",
                               msg="File integrity compromised. Not shown."), 422

    ext = row["orig_name"].rsplit(".", 1)[-1].lower()
    text_preview = image_uri = None
    if ext == "txt":
        text_preview = plain[:2000].decode("utf-8", errors="replace")
    elif ext in IMG_MIME and len(plain) <= 5 * 1024 * 1024:
        image_uri = f"data:{IMG_MIME[ext]};base64," + base64.b64encode(plain).decode()

    h = lab_core.hash_report(plain, row["sha256"])
    t0 = time.perf_counter()
    sig_ok = bool(row["signature"]) and verify_file_record(
        VERIFY_KEY, file_id, row["sha256"], row["signature"])
    ver_ms = (time.perf_counter() - t0) * 1000
    tampered = row["sha256"][:-1] + ("0" if row["sha256"][-1] != "0" else "1")
    tamper_ok = bool(row["signature"]) and verify_file_record(
        VERIFY_KEY, file_id, tampered, row["signature"])
    mb = max(len(plain), 1) / 1048576
    log_event("FILE_INSPECT", filename=row["orig_name"],
              detail="plaintext and ciphertext viewed")
    return render_template(
        "inspect.html", f=row, ext=ext, size=len(plain), blob_size=len(blob),
        nonce=blob[:12].hex(), tag=blob[12:28].hex(),
        cipher_hex=lab_core.hexdump(blob[28:], 96),
        plain_hex=lab_core.hexdump(plain, 96),
        cipher_b64=base64.b64encode(blob[28:28 + 16384]).decode(),
        text_preview=text_preview, image_uri=image_uri,
        dec_ms=dec_ms, dec_mbps=mb / (max(dec_ms, 1e-6) / 1000),
        enc_mbps=(mb / (row["enc_ms"] / 1000)) if row["enc_ms"] else None,
        h=h, sig_ok=sig_ok, ver_ms=ver_ms, tamper_ok=tamper_ok,
        aval=lab_core.avalanche(data_key, plain, trials=100))


@app.route("/lab", methods=["GET", "POST"])
@login_required
def lab():
    """Type any text: see plaintext, ciphertext, decryption, hash, signature, avalanche."""
    res = None
    if request.method == "POST":
        text = request.form.get("text", "")[:2000]
        tamper = request.form.get("tamper") == "1"
        data = text.encode()
        key, nonce = os.urandom(32), os.urandom(12)
        AES.new(key, AES.MODE_GCM, nonce=nonce).encrypt_and_digest(b"warm-up")
        t0 = time.perf_counter()
        ct, tag = AES.new(key, AES.MODE_GCM, nonce=nonce).encrypt_and_digest(data)
        enc_ms = (time.perf_counter() - t0) * 1000
        ct_used = lab_core.flip(ct, 0) if (tamper and ct) else ct
        t0 = time.perf_counter()
        try:
            back = AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct_used, tag)
            back_text, ok = back.decode("utf-8", errors="replace"), True
        except ValueError:
            back_text, ok = "", False
        dec_ms = (time.perf_counter() - t0) * 1000
        digest = sha256_hex(data)
        t0 = time.perf_counter()
        sig = sign_file_record(SIGN_KEY, "lab", digest)
        sign_ms = (time.perf_counter() - t0) * 1000
        t0 = time.perf_counter()
        sig_ok = verify_file_record(VERIFY_KEY, "lab", digest, sig)
        ver_ms = (time.perf_counter() - t0) * 1000
        res = dict(text=text, nonce=nonce.hex(), tag=tag.hex(), ct_hex=ct.hex(),
                   ct_b64=base64.b64encode(ct).decode(), tamper=tamper, ok=ok,
                   back=back_text, enc_ms=enc_ms, dec_ms=dec_ms, size=len(data),
                   h=lab_core.hash_report(data), sig=sig, sign_ms=sign_ms,
                   ver_ms=ver_ms, sig_ok=sig_ok,
                   aval=lab_core.avalanche(key, data or b"x", trials=100))
        log_event("CRYPTO_LAB", detail=f"text of {len(data)} bytes encrypted in the lab")
    return render_template("lab.html", r=res)


@app.route("/perf")
@login_required
def perf():
    rows = lab_core.perf_series()
    return render_template(
        "perf.html", rows=rows,
        chart_time=lab_core.svg_chart(rows, "enc_ms", "dec_ms",
                                      "Time vs data size", "Time (ms)"),
        chart_speed=lab_core.svg_chart(rows, "enc_mbps", "dec_mbps",
                                       "Speed vs data size", "Speed (MB/s)"))

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--insecure", action="store_true",
                    help="plain HTTP on port 5000 (for the Wireshark 'before' demo ONLY)")
    ap.add_argument("--host", default="127.0.0.1",
                    help="use 0.0.0.0 so other devices on the network can connect")
    ap.add_argument("--debug", action="store_true", help="development mode")
    a = ap.parse_args()
    if a.insecure:
        print("!! INSECURE MODE: traffic is NOT encrypted. Demo use only.")
        app.run(host=a.host, port=5000, debug=a.debug, threaded=True)
    else:
        cert, key = ensure_cert()
        app.config["SESSION_COOKIE_SECURE"] = True
        app.run(host=a.host, port=5443, debug=a.debug, threaded=True,
                ssl_context=(cert, key))