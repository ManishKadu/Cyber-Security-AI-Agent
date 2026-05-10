"""
agents/vuln_scanner.py - Vulnerability Scanner Agent
=====================================================
Scans code snippets, API configurations, and Docker setups
for common security weaknesses (OWASP Top 10, CWE patterns).
"""

import re
from utils.llm import call_llm
from utils.display import print_agent_header, print_finding, print_result


# ---------------------------------------------------------------------------
# Rule-based vulnerability patterns (fast first pass)
# ---------------------------------------------------------------------------

VULN_PATTERNS = {
    # Code-level vulnerabilities
    "HARDCODED_SECRET": {
        "patterns": [
            r'(?:password|passwd|pwd|secret|api_key|apikey|token|auth)\s*[=:]\s*["\'][^"\']{4,}["\']',
            r'(?:AWS_SECRET|PRIVATE_KEY|DATABASE_URL)\s*=\s*["\'][^"\']+["\']',
        ],
        "severity": "CRITICAL",
        "cwe": "CWE-798",
        "description": "Hardcoded credentials or secrets in source code",
    },
    "SQL_INJECTION_RISK": {
        "patterns": [
            r'f["\'].*(?:SELECT|INSERT|UPDATE|DELETE).*\{',
            r'["\'].*(?:SELECT|INSERT|UPDATE|DELETE).*["\']\s*%\s*\(',
            r'\.format\(.*(?:SELECT|INSERT|UPDATE|DELETE)',
            r'execute\([^)]*\+',
        ],
        "severity": "CRITICAL",
        "cwe": "CWE-89",
        "description": "Possible SQL injection via string concatenation/formatting",
    },
    "XSS_RISK": {
        "patterns": [
            r'innerHTML\s*=',
            r'document\.write\(',
            r'v-html\s*=',
            r'\|\s*safe\b',
        ],
        "severity": "HIGH",
        "cwe": "CWE-79",
        "description": "Potential Cross-Site Scripting (XSS) vulnerability",
    },
    "INSECURE_DESERIALIZATION": {
        "patterns": [
            r'pickle\.loads?\(',
            r'yaml\.load\([^)]*(?!Loader)',
            r'eval\(.*request',
            r'exec\(.*input',
        ],
        "severity": "CRITICAL",
        "cwe": "CWE-502",
        "description": "Insecure deserialization — possible remote code execution",
    },
    "WEAK_CRYPTO": {
        "patterns": [
            r'(?:md5|sha1)\s*\(',
            r'DES\b|RC4\b|Blowfish',
            r'ECB\b',
        ],
        "severity": "MEDIUM",
        "cwe": "CWE-327",
        "description": "Weak or broken cryptographic algorithm in use",
    },
    "DEBUG_ENABLED": {
        "patterns": [
            r'DEBUG\s*=\s*True',
            r'app\.debug\s*=\s*True',
            r'FLASK_DEBUG\s*=\s*1',
        ],
        "severity": "MEDIUM",
        "cwe": "CWE-489",
        "description": "Debug mode enabled — exposes stack traces and internals",
    },
    "SSRF_RISK": {
        "patterns": [
            r'requests\.get\(.*(?:request\.|input|param)',
            r'urllib\.request\.urlopen\(.*(?:request\.|input)',
        ],
        "severity": "HIGH",
        "cwe": "CWE-918",
        "description": "Potential Server-Side Request Forgery (SSRF)",
    },
    "INSECURE_FILE_UPLOAD": {
        "patterns": [
            r'\.save\(.*filename\)',
            r'upload.*without.*validation',
        ],
        "severity": "HIGH",
        "cwe": "CWE-434",
        "description": "File upload without proper validation",
    },
    # Docker-specific
    "DOCKER_ROOT": {
        "patterns": [
            r'USER\s+root',
            r'^(?!.*USER\s).*FROM\s',  # No USER directive
        ],
        "severity": "MEDIUM",
        "cwe": "CWE-250",
        "description": "Container running as root user",
    },
    "DOCKER_LATEST": {
        "patterns": [
            r'FROM\s+\w+:latest',
            r'FROM\s+\w+\s*$',
        ],
        "severity": "LOW",
        "cwe": "CWE-1104",
        "description": "Using 'latest' or untagged image — unpinned dependency",
    },
}


SAMPLE_VULNERABLE_CODE = '''
# === Sample App (intentionally vulnerable for demo) ===
import sqlite3
import pickle
import hashlib
from flask import Flask, request

app = Flask(__name__)
app.debug = True
DATABASE_URL = "sqlite:///mydb.db"
API_KEY = "sk-secret-key-12345-do-not-share"

@app.route("/login")
def login():
    username = request.args.get("username")
    password = request.args.get("password")

    # BAD: SQL Injection
    query = f"SELECT * FROM users WHERE name='{username}' AND pass='{password}'"
    conn = sqlite3.connect("mydb.db")
    result = conn.execute(query)

    # BAD: Weak hashing
    hashed = hashlib.md5(password.encode()).hexdigest()

    return str(result.fetchall())

@app.route("/profile")
def profile():
    # BAD: XSS via innerHTML equivalent
    bio = request.args.get("bio")
    return f"<div>{bio}</div>"

@app.route("/load")
def load_data():
    # BAD: Insecure deserialization
    data = request.get_data()
    obj = pickle.loads(data)
    return str(obj)

@app.route("/fetch")
def fetch_url():
    # BAD: SSRF
    import requests as req
    url = request.args.get("url")
    return req.get(url).text
'''


def _scan_code(code: str) -> list[dict]:
    """Run regex-based vulnerability scan on code."""
    findings = []
    for vuln_name, vuln in VULN_PATTERNS.items():
        for pattern in vuln["patterns"]:
            matches = re.findall(pattern, code, re.IGNORECASE | re.MULTILINE)
            if matches:
                findings.append({
                    "vulnerability": vuln_name,
                    "severity": vuln["severity"],
                    "cwe": vuln["cwe"],
                    "description": vuln["description"],
                    "matches": len(matches),
                })
                break  # One match per vulnerability type is enough
    return findings


def run(code: str = None, use_sample: bool = False) -> dict:
    """
    Scan code for security vulnerabilities.

    Args:
        code: Source code string to scan
        use_sample: If True, use built-in vulnerable sample code for demo

    Returns:
        Dictionary with findings and AI remediation advice
    """
    print_agent_header("VULNERABILITY SCANNER AGENT", "🔓")

    if use_sample or code is None:
        code = SAMPLE_VULNERABLE_CODE
        print("  📝 Using built-in sample vulnerable code for demo")

    # Step 1: Rule-based scan
    findings = _scan_code(code)
    print(f"\n  🔍 Static analysis found {len(findings)} vulnerabilities:")

    for f_item in findings:
        print_finding(
            f_item["severity"],
            f'{f_item["vulnerability"]} ({f_item["cwe"]})',
            f_item["description"],
        )

    # Step 2: AI deep scan
    system_prompt = """You are a senior application security engineer performing
a code review. Analyze the code for:
1. OWASP Top 10 vulnerabilities
2. CWE-classified weaknesses
3. Business logic flaws
4. Authentication/authorization issues
5. Dependency risks

For each vulnerability found:
- Assign severity (CRITICAL/HIGH/MEDIUM/LOW)
- Reference the CWE ID
- Show the vulnerable code line
- Provide the FIXED version of the code
- Explain the attack scenario

Use markdown formatting. Be thorough but concise."""

    prompt = f"""Scan this code for security vulnerabilities:

```python
{code}
```

Rule-based scan already found: {[f['vulnerability'] for f in findings]}

Look deeper for anything the rules missed. Provide fixed code snippets."""

    print("\n  🧠 Running AI-powered deep code review...")
    ai_analysis = call_llm(prompt, system_prompt)
    print_result(ai_analysis)

    return {
        "agent": "vuln_scanner",
        "total_findings": len(findings),
        "findings": findings,
        "ai_analysis": ai_analysis,
    }
