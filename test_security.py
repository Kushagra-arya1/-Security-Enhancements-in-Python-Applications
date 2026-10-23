"""test_security.py - Security Validation & Attack Simulation Suite"""
import unittest, os
from pathlib import Path
import secure_app

class SecurityValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        secure_app.DB_FILE = "test_vault.db"
        secure_app.BASE_DIR = Path("test_safe_files").resolve()
        secure_app.BASE_DIR.mkdir(parents=True, exist_ok=True)
        for f in secure_app.BASE_DIR.glob("*"):
            if f.is_file():
                try: f.unlink()
                except OSError: pass
        if os.path.exists(secure_app.DB_FILE):
            try: os.remove(secure_app.DB_FILE)
            except OSError: pass
        secure_app.init_db()

    @classmethod
    def tearDownClass(cls):
        if secure_app.BASE_DIR.exists():
            for f in secure_app.BASE_DIR.glob("*"):
                if f.is_file():
                    try: f.unlink()
                    except OSError: pass
        if os.path.exists(secure_app.DB_FILE):
            try: os.remove(secure_app.DB_FILE)
            except OSError: pass

    def test_01_sql_injection_defense(self):
        """Simulate SQL injection authentication bypass."""
        secure_app.register_user("alice", "SuperSecret#2026")
        payloads = ["' OR '1'='1' --", "admin' --", "' UNION SELECT 1, 'x', 'y' --"]
        for p in payloads:
            self.assertFalse(secure_app.authenticate(p, "random_pwd"))
            self.assertFalse(secure_app.authenticate("alice", p))

    def test_02_password_hashing_and_salting(self):
        """Verify no plaintext passwords and unique per-user salts."""
        secure_app.register_user("bob", "SharedPassword123")
        secure_app.register_user("charlie", "SharedPassword123")
        with secure_app.get_db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT username, salt, pwhash FROM users WHERE username IN ('bob', 'charlie')")
            rows = {r[0]: (r[1], r[2]) for r in cur.fetchall()}
            self.assertNotEqual(rows["bob"][0], rows["charlie"][0], "Salts must be unique per user")
            self.assertNotEqual(rows["bob"][1], rows["charlie"][1], "Hashes must differ even for identical passwords")
            self.assertNotIn(b"SharedPassword123", rows["bob"][1], "Password must never be stored as plaintext")

    def test_03_path_traversal_defense(self):
        """Simulate directory traversal attacks."""
        valid_file = secure_app.BASE_DIR / "welcome.txt"
        valid_file.write_text("Hello Safe World", encoding="utf-8")
        self.assertEqual(secure_app.read_safe_file("welcome.txt"), "Hello Safe World")

        traversal_attempts = ["../../vulnerable_app.py", "..\\..\\test.txt", "/etc/passwd", "C:\\Windows\\system.ini"]
        for malicious_path in traversal_attempts:
            with self.assertRaises((PermissionError, ValueError)):
                secure_app.read_safe_file(malicious_path)

    def test_04_command_injection_defense(self):
        """Simulate command injection payloads in diagnostic tool."""
        injections = ["127.0.0.1 & whoami", "127.0.0.1; dir", "google.com | calc.exe", "localhost && id"]
        for payload in injections:
            with self.assertRaises(ValueError):
                secure_app.ping_diagnostic(payload)

    def test_05_valid_authentication_flow(self):
        """Ensure legitimate operational flow is preserved."""
        self.assertTrue(secure_app.authenticate("alice", "SuperSecret#2026"))
        self.assertFalse(secure_app.authenticate("alice", "WrongPassword!"))

if __name__ == "__main__":
    unittest.main()
