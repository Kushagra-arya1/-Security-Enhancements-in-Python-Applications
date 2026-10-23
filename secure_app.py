"""secure_app.py - Hardened, Secure Python Application (Zero-Dependency)"""
import os, re, sqlite3, hashlib, secrets, hmac, subprocess, logging
from pathlib import Path
from contextlib import contextmanager

DB_FILE = "secure_vault.db"
BASE_DIR = Path("safe_user_files").resolve()
logging.basicConfig(filename="app_security.log", level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

USER_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,20}$")
HOST_REGEX = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$|^\d{1,3}(?:\.\d{1,3}){3}$")

@contextmanager
def get_db():
    conn = sqlite3.connect(DB_FILE)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

def init_db():
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    with get_db() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, salt BLOB, pwhash BLOB)")
        conn.execute("CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, username TEXT, note TEXT)")

def hash_password(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    salt = salt or secrets.token_bytes(16)
    pwhash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return salt, pwhash

# Fix 1 & 2: Input Validation, Parameterized Query, & Salted PBKDF2 Password Hashing
def register_user(username: str, password: str) -> bool:
    if not USER_REGEX.match(username) or len(password) < 8:
        raise ValueError("Invalid username (3-20 alphanum/_) or password too short (min 8 chars).")
    salt, pwhash = hash_password(password)
    try:
        with get_db() as conn:
            conn.execute("INSERT INTO users (username, salt, pwhash) VALUES (?, ?, ?)", (username, salt, pwhash))
            logging.info(f"User registered successfully: {username}")
            return True
    except sqlite3.IntegrityError:
        raise ValueError("Username already exists.")

def authenticate(username: str, password: str) -> bool:
    if not USER_REGEX.match(username):
        return False
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT salt, pwhash FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if not row:
            return False
        stored_salt, stored_hash = row
        _, calc_hash = hash_password(password, stored_salt)
        return hmac.compare_digest(stored_hash, calc_hash)

# Fix 3: Path Traversal Prevention (Strict Canonical Path Boundary Check)
def read_safe_file(filename: str) -> str:
    clean_name = os.path.basename(filename.strip().replace("\\", "/"))
    target = (BASE_DIR / clean_name).resolve()
    if not target.is_relative_to(BASE_DIR) or not target.is_file():
        raise PermissionError("Access denied: Invalid path or file outside allowed directory.")
    return target.read_text(encoding="utf-8")

# Fix 4: Command Injection Prevention (Allowlist validation + shell=False subprocess)
def ping_diagnostic(host: str) -> str:
    host = host.strip()
    if not HOST_REGEX.match(host):
        raise ValueError("Invalid target host. Must be a valid domain or IPv4 address.")
    res = subprocess.run(["ping", "-n", "1", host], capture_output=True, text=True, timeout=5, shell=False)
    return res.stdout

# Fix 5: Generic Safe Error Messaging (No sensitive stack traces exposed to user)
def run_cli():
    init_db()
    try:
        action = input("Select [1] Register, [2] Login: ").strip()
        u = input("Username: ").strip()
        p = input("Password: ").strip()
        if action == "1":
            register_user(u, p)
            print("Registration completed securely.")
        elif action == "2":
            if not authenticate(u, p):
                print("Authentication failed: Invalid credentials.")
                return
            print("Authentication successful.")
            opt = input("Select [1] Ping Host, [2] Read Document: ").strip()
            if opt == "1":
                h = input("Host: ").strip()
                print(ping_diagnostic(h))
            elif opt == "2":
                fn = input("Filename: ").strip()
                print(read_safe_file(fn))
    except Exception as e:
        logging.error(f"Application error: {e}")
        print(f"Error: {e}")

if __name__ == "__main__":
    run_cli()
