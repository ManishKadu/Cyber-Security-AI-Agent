"""
agents/log_monitor.py - Log Monitor Agent
==========================================
Reads system/network logs and uses AI to detect unusual activity,
brute force attacks, SQL injection attempts, and other threats.
"""

import re
from collections import Counter
from utils.llm import call_llm
from utils.display import print_agent_header, print_finding, print_result


# ---------------------------------------------------------------------------
# Rule-based pre-analysis (fast, no LLM needed)
# ---------------------------------------------------------------------------

ATTACK_PATTERNS = {
    "BRUTE_FORCE": {
        "pattern": r"Failed password|authentication failure|incorrect password",
        "severity": "HIGH",
        "description": "Multiple failed login attempts detected",
    },
    "SQL_INJECTION": {
        "pattern": r"SQL injection|union.*select|' OR '1'='1|admin'--|%27",
        "severity": "CRITICAL",
        "description": "SQL injection attempt detected",
    },
    "PATH_TRAVERSAL": {
        "pattern": r"/etc/shadow|/etc/passwd|\.\./\.\.",
        "severity": "HIGH",
        "description": "Path traversal / unauthorized file access attempt",
    },
    "PORT_SCAN": {
        "pattern": r"UFW BLOCK.*PROTO=TCP|SYN flooding|port scan",
        "severity": "MEDIUM",
        "description": "Possible port scan or SYN flood",
    },
    "SUSPICIOUS_CRON": {
        "pattern": r"cron.*(/tmp/|\.hidden|backdoor|reverse_shell)",
        "severity": "CRITICAL",
        "description": "Suspicious cron job executing from temp/hidden directory",
    },
    "DIRECTORY_ENUM": {
        "pattern": r"wp-admin|administrator|phpinfo|\.env",
        "severity": "MEDIUM",
        "description": "Web directory enumeration / recon activity",
    },
    "BREAK_IN_ATTEMPT": {
        "pattern": r"POSSIBLE BREAK-IN ATTEMPT|reverse mapping.*failed",
        "severity": "HIGH",
        "description": "Potential break-in attempt flagged by system",
    },
}


def _extract_ips(logs: str) -> dict:
    """Extract IP addresses and count their occurrences in failed attempts."""
    failed_lines = [l for l in logs.split("\n") if "Failed" in l or "failed" in l]
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "\n".join(failed_lines))
    return dict(Counter(ips).most_common(10))


def _rule_based_scan(logs: str) -> list[dict]:
    """Run fast regex-based detection on log lines."""
    findings = []
    for name, rule in ATTACK_PATTERNS.items():
        matches = re.findall(rule["pattern"], logs, re.IGNORECASE)
        if matches:
            findings.append({
                "rule": name,
                "severity": rule["severity"],
                "description": rule["description"],
                "match_count": len(matches),
            })
    return findings


# ---------------------------------------------------------------------------
# Main agent function
# ---------------------------------------------------------------------------

def run(log_file_path: str) -> dict:
    """
    Analyze log file for security threats.

    Args:
        log_file_path: Path to the log file to analyze

    Returns:
        Dictionary with findings, suspicious IPs, and AI analysis
    """
    print_agent_header("LOG MONITOR AGENT", "📋")

    # Step 1: Read logs
    with open(log_file_path, "r") as f:
        logs = f.read()

    total_lines = len(logs.strip().split("\n"))
    print(f"  📄 Loaded {total_lines} log lines from {log_file_path}")

    # Step 2: Rule-based detection (fast)
    findings = _rule_based_scan(logs)
    suspicious_ips = _extract_ips(logs)

    print(f"  🔍 Rule-based scan found {len(findings)} threat patterns")
    for f_item in findings:
        print_finding(f_item["severity"], f_item["rule"], f_item["description"])

    if suspicious_ips:
        print(f"\n  🌐 Top suspicious IPs:")
        for ip, count in suspicious_ips.items():
            print(f"     • {ip} — {count} failed attempts")

    # Step 3: AI-powered deep analysis
    system_prompt = """You are an expert cybersecurity log analyst. Analyze the
provided system logs and identify security threats. For each threat found:
1. Classify severity (CRITICAL / HIGH / MEDIUM / LOW)
2. Describe the attack type and technique (use MITRE ATT&CK if applicable)
3. Identify the source IP and target
4. Recommend immediate actions

Be concise and structured. Use markdown formatting."""

    prompt = f"""Analyze these system logs for security threats:

--- LOG DATA ---
{logs}
--- END LOGS ---

Rule-based scan already found: {findings}
Suspicious IPs: {suspicious_ips}

Provide a deep analysis covering anything the rules might have missed,
correlations between events, and an overall threat assessment."""

    print("\n  🧠 Running AI-powered deep analysis...")
    ai_analysis = call_llm(prompt, system_prompt)
    print_result(ai_analysis)

    return {
        "agent": "log_monitor",
        "total_lines": total_lines,
        "findings": findings,
        "suspicious_ips": suspicious_ips,
        "ai_analysis": ai_analysis,
    }
