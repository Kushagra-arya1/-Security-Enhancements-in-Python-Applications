"""vulnerable_app.py - Demonstration of Common Python Security Flaws (Pre-Hardening)"""
import os, sqlite3, traceback

DB_FILE = "vulnerable.db"

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, username TEXT, note TEXT)")
        conn.commit()

# Vulnerability 1 & 2: Plaintext password storage + SQL Injection in registration & login
def register(username, password):
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')")
        conn.commit()

def login(username, password):
    with sqlite3.connect(DB_FILE) as conn:
        # SQL Injection flaw: string formatting directly into SQL query
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        cur = conn.cursor()
        cur.execute(query)
        return cur.fetchone()

# Vulnerability 3: Path Traversal
def read_user_file(filename):
    # No path sanitization: allows ../../ escape to sensitive files
    path = os.path.join("user_files", filename)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

# Vulnerability 4: Command Injection
def ping_host(host):
    # Command injection flaw: shell=True / os.system with unsanitized user input
    return os.system(f"ping -n 1 {host}")

# Vulnerability 5: Improper Error Handling / Information Leakage
def run_cli():
    init_db()
    os.makedirs("user_files", exist_ok=True)
    try:
        user = input("Username: ")
        pwd = input("Password: ")
        if login(user, pwd):
            print("Login success!")
            host = input("Ping host: ")
            ping_host(host)
            doc = input("File to read: ")
            print(read_user_file(doc))
        else:
            print("Invalid credentials")
    except Exception:
        # Leaks full stack trace, system environment, and internal file paths
        traceback.print_exc()

if __name__ == "__main__":
    run_cli()
