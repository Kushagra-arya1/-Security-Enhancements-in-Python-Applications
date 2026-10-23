# Security Enhancements in Python Applications

A self-contained Python security benchmark demonstrating vulnerability identification, threat mitigation, and code hardening following OWASP secure coding standards.

---

## 📁 Repository Structure & Mini Line Descriptions

| File | Lines | Mini Line Description |
|---|---|---|
| [`vulnerable_app.py`](vulnerable_app.py) | 58 | Baseline exhibiting 5 OWASP flaws (SQLi, cleartext credentials, command injection, path traversal, stack trace leakage). |
| [`secure_app.py`](secure_app.py) | 102 | Hardened implementation using parameterized queries, salted PBKDF2 hashing, regex whitelisting, and path containment. |
| [`test_security.py`](test_security.py) | 76 | Automated `unittest` suite simulating attacks (SQL injection, directory traversal, shell escaping, rainbow-table resistance). |
| [`SECURITY_REPORT.md`](SECURITY_REPORT.md) | 121 | Comprehensive audit report covering CVSS v3.1 ratings, real-world attack scenarios, and before/after code diffs. |
| [`submission.zip`](submission.zip) | Binary | Self-contained submission archive containing all hardened source files, tests, and documentation. |

---

## 🛡️ Vulnerability Remediation Matrix

| Vulnerability | OWASP Mapping | Severity | Implemented Fix |
|---|---|---|---|
| **SQL Injection** | A03:2021 - Injection | Critical (9.8) | SQLite parameterized queries (`?` binding) |
| **Plaintext Passwords** | A02:2021 - Cryptographic Failures | High (8.1) | PBKDF2-HMAC-SHA256 (100k rounds) + unique 16-byte salt |
| **Command Injection** | A03:2021 - Injection | Critical (9.8) | Strict host regex allowlist + `subprocess.run(shell=False)` |
| **Path Traversal** | A01:2021 - Broken Access Control | High (7.5) | `os.path.basename` + canonical `is_relative_to` containment |
| **Information Disclosure** | A05:2021 - Security Misconfiguration | Medium (5.3) | Generic client errors + internal isolated file logging |

---

## 🚀 Quickstart & Testing

### 1. Run Automated Security Test Suite
Simulates real-world attack payloads against the hardened application:
```bash
python -m unittest test_security.py
```
**Expected Output:**
```text
.....
----------------------------------------------------------------------
Ran 5 tests in 0.705s

OK
```

### 2. Run Hardened Application
```bash
python secure_app.py
```

### 3. Run Baseline (Vulnerable Demonstration)
```bash
python vulnerable_app.py
```