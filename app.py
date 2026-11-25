"""
Backend server for the Decoder control panel.
---------------------------------------------
Holds the live state that the website checks (site up/down, password
barrier, encode toggle, broadcast banner) plus a log of every message
decoded/encoded on the site.

  Public endpoints (used by the website):
    GET  /api/state     -> current public state (no secrets)
    POST /api/unlock    -> {"password": "..."} -> {"success": true/false}
    POST /api/log       -> {"mode": "...", "text": "..."} -> logs a message

  Admin endpoints (used by the control panel, need X-Admin-Key header):
    GET  /api/admin/status     -> full status
    POST /api/admin/heartbeat  -> "control panel is open" ping
    POST /api/admin/enable     -> {"enabled": true/false}
    POST /api/admin/password   -> {"required": bool, "password": "..."}
    POST /api/admin/encode     -> {"enabled": true/false}
    POST /api/admin/broadcast  -> {"active", "text", "scroll", "takeover"}
    GET  /api/admin/log        -> logged messages (newest first)

Everything is stored in small files next to this script (state.json,
log.json, heartbeat.txt) and re-read on every request, so it behaves
correctly even if the host runs several worker processes.

ADMIN KEY: generated on first start and saved to admin_key.txt. On hosts
whose disk is wiped on every redeploy (e.g. Render's free tier) set an
ADMIN_KEY environment variable instead so the key never changes.

Run locally:
    pip install -r requirements.txt
    python app.py
Run in production:
    gunicorn app:app
"""

import hashlib
import json
import os
import secrets
import threading
import time
from contextlib import contextmanager

from flask import Flask, jsonify, request
from flask_cors import CORS

try:
    import fcntl  # Linux/macOS: lets separate worker processes take turns
except ImportError:  # Windows
    fcntl = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(BASE_DIR, "state.json")
LOG_FILE = os.path.join(BASE_DIR, "log.json")
HEARTBEAT_FILE = os.path.join(BASE_DIR, "heartbeat.txt")
ADMIN_KEY_FILE = os.path.join(BASE_DIR, "admin_key.txt")
LOCK_FILE = os.path.join(BASE_DIR, ".lock")

MAX_LOG_ENTRIES = 500

# The control panel pings every 3 seconds. If 15 seconds pass with no
# ping (panel closed, server asleep, network down) the site shows "down".
HEARTBEAT_TIMEOUT = 15

PASSWORD_ITERATIONS = 200_000
UNLOCK_ATTEMPTS_PER_MINUTE = 10
LOG_POSTS_PER_MINUTE = 30

DEFAULT_BROADCAST = {"active": False, "text": "", "scroll": False, "takeover": False}
DEFAULT_STATE = {
    "enabled": True,
    "password_required": False,
    "password_hash": None,
    "password_salt": None,
    "password_version": 0,   # bumps whenever the password changes / is re-required
    "encode_enabled": False,
    "broadcast": DEFAULT_BROADCAST,
}

_thread_lock = threading.RLock()


@contextmanager
def store_lock():
    """One-at-a-time access to the data files, across threads AND processes."""
    with _thread_lock:
        handle = None
        if fcntl is not None:
            try:
                handle = open(LOCK_FILE, "a")
                fcntl.flock(handle, fcntl.LOCK_EX)
            except Exception:
                handle = None
        try:
            yield
        finally:
            if handle is not None:
                try:
                    fcntl.flock(handle, fcntl.LOCK_UN)
                finally:
                    handle.close()


def atomic_write(path, text):
    """Write to a temp file then swap it in, so a reader never sees a
    half-written (empty) file."""
    tmp = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.replace(tmp, path)


def read_file(path, tries=5):
    """Read a file, retrying briefly. A file being swapped on a slow or
    network disk can look 'missing' for a split second. Returns None if
    it really isn't there."""
    for attempt in range(tries):
        try:
            with open(path) as f:
                return f.read()
        except FileNotFoundError:
            time.sleep(0.01 * (attempt + 1))
    return None


def load_state():
    state = {**DEFAULT_STATE, "broadcast": dict(DEFAULT_BROADCAST)}
    raw = read_file(STATE_FILE)
    if raw is None:
        return state  # first run: nothing saved yet
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("state file is not an object")
        state.update({k: v for k, v in data.items() if k != "broadcast"})
        if isinstance(data.get("broadcast"), dict):
            state["broadcast"].update(data["broadcast"])
        return state
    except Exception:
        # Unreadable state file: fail CLOSED (site down) rather than
        # silently falling back to "open, no password".
        state["enabled"] = False
        return state


def save_state(state):
    atomic_write(STATE_FILE, json.dumps(state, indent=2))


def load_log():
    raw = read_file(LOG_FILE)
    if raw is not None:
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                return data
        except Exception:
            pass
    return []


def save_log(entries):
    atomic_write(LOG_FILE, json.dumps(entries[-MAX_LOG_ENTRIES:], indent=2))


def read_heartbeat():
    raw = read_file(HEARTBEAT_FILE)
    try:
        return float(raw.strip()) if raw else 0.0
    except ValueError:
        return 0.0


def write_heartbeat(ts):
    atomic_write(HEARTBEAT_FILE, str(ts))


def get_or_create_admin_key():
    env_key = os.environ.get("ADMIN_KEY", "").strip()
    if env_key:
        return env_key
    if os.path.exists(ADMIN_KEY_FILE):
        with open(ADMIN_KEY_FILE) as f:
            key = f.read().strip()
            if key:
                return key
    key = secrets.token_urlsafe(24)
    atomic_write(ADMIN_KEY_FILE, key)
    return key


ADMIN_KEY = get_or_create_admin_key()

app = Flask(__name__)
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "*")
CORS(app, resources={r"/api/*": {"origins": ALLOWED_ORIGIN}})

# ---------- small helpers ----------

_rate_hits = {}  # (bucket, ip) -> list of timestamps (per process)


def client_ip():
    # Behind a host's proxy the real client is the LAST address it appended.
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[-1].strip()
    return request.remote_addr or "unknown"


def rate_limited(bucket, limit, window=60):
    now = time.time()
    key = (bucket, client_ip())
    hits = [t for t in _rate_hits.get(key, []) if now - t < window]
    if len(hits) >= limit:
        _rate_hits[key] = hits
        return True
    hits.append(now)
    _rate_hits[key] = hits
    if len(_rate_hits) > 5000:  # keep memory bounded
        for k in list(_rate_hits)[:2500]:
            _rate_hits.pop(k, None)
    return False


def json_body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def is_admin_request():
    key = request.headers.get("X-Admin-Key", "")
    return secrets.compare_digest(key.encode(), ADMIN_KEY.encode())


def control_panel_alive():
    return (time.time() - read_heartbeat()) <= HEARTBEAT_TIMEOUT


def site_is_up(state):
    return bool(state["enabled"]) and control_panel_alive()


def public_state(state):
    return {
        "enabled": site_is_up(state),
        "password_required": state["password_required"],
        "password_version": state["password_version"],
        "encode_enabled": state["encode_enabled"],
        "broadcast": state["broadcast"],
    }


def hash_password(password, salt_hex):
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), PASSWORD_ITERATIONS
    ).hex()


def password_matches(state, password):
    if state.get("password_salt"):
        given = hash_password(password, state["password_salt"])
    else:  # older saved password (plain SHA-256, no salt)
        given = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return secrets.compare_digest(given, state["password_hash"] or "")


def unauthorized():
    return jsonify({"error": "unauthorized"}), 401


# ---------- public endpoints ----------

@app.get("/")
def index():
    return jsonify({"ok": True, "service": "decoder-backend"})


@app.get("/api/state")
def get_state():
    with store_lock():
        return jsonify(public_state(load_state()))


@app.post("/api/unlock")
def unlock():
    if rate_limited("unlock", UNLOCK_ATTEMPTS_PER_MINUTE):
        return jsonify({"success": False, "error": "too many attempts"}), 429
    password = str(json_body().get("password", ""))
    with store_lock():
        state = load_state()
    if not site_is_up(state):
        return jsonify({"success": False, "error": "site disabled"}), 403
    if not state["password_required"]:
        return jsonify({"success": True, "password_version": state["password_version"]})
    if not state["password_hash"]:
        return jsonify({"success": False, "error": "no password set"}), 400
    ok = password_matches(state, password)
    return jsonify({"success": ok, "password_version": state["password_version"]})


@app.post("/api/log")
def add_log():
    """Called by the website whenever a decode/encode result is produced.
    Anonymous by design, so it is rate limited, size limited, and ignored
    while the site is down."""
    if rate_limited("log", LOG_POSTS_PER_MINUTE):
        return jsonify({"error": "slow down"}), 429
    data = json_body()
    mode = data.get("mode")
    text = str(data.get("text") or "").strip()
    if mode not in ("encode", "decode") or not text:
        return jsonify({"error": "invalid entry"}), 400
    with store_lock():
        if not site_is_up(load_state()):
            return jsonify({"error": "site disabled"}), 403
        entries = load_log()
        entries.append({
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "mode": mode,
            "text": text[:1000],
        })
        save_log(entries)
    return jsonify({"ok": True})


# ---------- admin endpoints ----------

@app.get("/api/admin/status")
def admin_status():
    if not is_admin_request():
        return unauthorized()
    with store_lock():
        state = load_state()
    return jsonify({
        **public_state(state),
        "raw_enabled": state["enabled"],
        "password_set": bool(state["password_hash"]),
        "panel_alive": control_panel_alive(),
    })


@app.post("/api/admin/heartbeat")
def admin_heartbeat():
    """The control panel pings this every few seconds while open.
    {"offline": true} is sent when the panel is closed on purpose so the
    site goes down immediately instead of after the timeout."""
    if not is_admin_request():
        return unauthorized()
    write_heartbeat(0.0 if json_body().get("offline") else time.time())
    return jsonify({"ok": True})


@app.post("/api/admin/enable")
def admin_enable():
    if not is_admin_request():
        return unauthorized()
    data = json_body()
    if not isinstance(data.get("enabled"), bool):
        return jsonify({"error": "'enabled' (true/false) is required"}), 400
    with store_lock():
        state = load_state()
        state["enabled"] = data["enabled"]
        save_state(state)
    return jsonify(public_state(state))


@app.post("/api/admin/password")
def admin_password():
    if not is_admin_request():
        return unauthorized()
    data = json_body()
    with store_lock():
        state = load_state()
        changed = False
        if isinstance(data.get("required"), bool):
            if data["required"] and not state["password_required"]:
                changed = True  # turning the barrier back on re-locks everyone
            state["password_required"] = data["required"]
        password = data.get("password")
        if isinstance(password, str) and password:
            salt = secrets.token_hex(16)
            state["password_salt"] = salt
            state["password_hash"] = hash_password(password, salt)
            changed = True
        if changed:
            state["password_version"] = int(state.get("password_version", 0)) + 1
        save_state(state)
    return jsonify({**public_state(state), "password_set": bool(state["password_hash"])})


@app.post("/api/admin/encode")
def admin_encode():
    if not is_admin_request():
        return unauthorized()
    data = json_body()
    if not isinstance(data.get("enabled"), bool):
        return jsonify({"error": "'enabled' (true/false) is required"}), 400
    with store_lock():
        state = load_state()
        state["encode_enabled"] = data["enabled"]
        save_state(state)
    return jsonify(public_state(state))


@app.post("/api/admin/broadcast")
def admin_broadcast():
    if not is_admin_request():
        return unauthorized()
    data = json_body()
    with store_lock():
        state = load_state()
        b = state["broadcast"]
        if isinstance(data.get("active"), bool):
            b["active"] = data["active"]
        if "text" in data:
            b["text"] = str(data["text"])[:500]
        if isinstance(data.get("scroll"), bool):
            b["scroll"] = data["scroll"]
        if isinstance(data.get("takeover"), bool):
            b["takeover"] = data["takeover"]
        save_state(state)
    return jsonify(public_state(state))


@app.get("/api/admin/log")
def get_log():
    if not is_admin_request():
        return unauthorized()
    with store_lock():
        entries = load_log()
    return jsonify(list(reversed(entries[-MAX_LOG_ENTRIES:])))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print("=" * 60)
    print(f"Admin key (paste this into the control panel): {ADMIN_KEY}")
    print("=" * 60)
    app.run(host="0.0.0.0", port=port)
