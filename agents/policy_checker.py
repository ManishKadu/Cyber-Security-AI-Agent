"""
agents/policy_checker.py - Policy Checker Agent
================================================
Audits system configuration against security frameworks:
ISO 27001, NIST CSF, SOC 2, CIS Benchmarks.
"""

import yaml
from utils.llm import call_llm
from utils.display import print_agent_header, print_finding, print_result


# ---------------------------------------------------------------------------
# Rule-based policy checks (deterministic, fast)
# ---------------------------------------------------------------------------

def _check_policies(config: dict) -> list[dict]:
    """Run deterministic policy checks against known frameworks."""
    findings = []

    # --- Authentication Checks (NIST IA, ISO A.9) ---
    auth = config.get("authentication", {})
    pw = auth.get("password_policy", {})

    if pw.get("min_length", 0) < 12:
        findings.append({
            "control": "NIST IA-5 / ISO A.9.4.3",
            "severity": "HIGH",
            "title": "Weak password length policy",
            "detail": f"Minimum length is {pw.get('min_length', 'N/A')} (should be ≥12)",
            "fix": "Set password_policy.min_length to 12 or higher",
        })

    if not pw.get("require_special_char", False):
        findings.append({
            "control": "NIST IA-5 / CIS 5.3.1",
            "severity": "MEDIUM",
            "title": "No special character requirement",
            "detail": "Passwords don't require special characters",
            "fix": "Set require_special_char to true",
        })

    if pw.get("max_age_days", 0) == 0:
        findings.append({
            "control": "NIST IA-5 / SOC2 CC6.1",
            "severity": "MEDIUM",
            "title": "Password never expires",
            "detail": "No password rotation policy configured",
            "fix": "Set max_age_days to 90 (or use passkeys/MFA instead)",
        })

    if not auth.get("mfa_enabled", False):
        findings.append({
            "control": "NIST IA-2(1) / ISO A.9.4.2 / SOC2 CC6.1",
            "severity": "CRITICAL",
            "title": "Multi-Factor Authentication disabled",
            "detail": "MFA is not enabled — single factor only",
            "fix": "Enable MFA for all user accounts, especially admin",
        })

    if auth.get("root_login_allowed", True):
        findings.append({
            "control": "CIS 5.2.10 / NIST AC-6",
            "severity": "HIGH",
            "title": "Root login is allowed",
            "detail": "Direct root SSH login is permitted",
            "fix": "Set root_login_allowed to false; use sudo instead",
        })

    # --- Network Checks (NIST SC, ISO A.13) ---
    net = config.get("network", {})

    risky_ports = [p for p in net.get("open_ports", []) if p in [3306, 3389, 445, 135, 1433, 5432]]
    if risky_ports:
        findings.append({
            "control": "NIST SC-7 / ISO A.13.1.1 / CIS 9.2",
            "severity": "HIGH",
            "title": "High-risk ports exposed",
            "detail": f"Ports {risky_ports} are open (database/RDP/SMB)",
            "fix": "Close these ports or restrict to trusted IPs only",
        })

    ssl = net.get("ssl_version", "")
    if ssl in ["TLSv1.0", "TLSv1.1", "SSLv3"]:
        findings.append({
            "control": "NIST SC-8 / SOC2 CC6.7 / PCI DSS 4.1",
            "severity": "CRITICAL",
            "title": "Deprecated TLS/SSL version",
            "detail": f"Using {ssl} which has known vulnerabilities",
            "fix": "Upgrade to TLS 1.2 or TLS 1.3",
        })

    if not net.get("hsts_enabled", False):
        findings.append({
            "control": "NIST SC-8 / OWASP",
            "severity": "MEDIUM",
            "title": "HSTS not enabled",
            "detail": "HTTP Strict Transport Security header not configured",
            "fix": "Enable HSTS with a min 1-year max-age",
        })

    # --- Logging Checks (NIST AU, ISO A.12.4) ---
    log = config.get("logging", {})

    if not log.get("audit_logging", False):
        findings.append({
            "control": "NIST AU-2 / ISO A.12.4.1 / SOC2 CC7.2",
            "severity": "HIGH",
            "title": "Audit logging disabled",
            "detail": "Security events are not being recorded",
            "fix": "Enable audit_logging and configure auditd",
        })

    if log.get("log_retention_days", 0) < 90:
        findings.append({
            "control": "NIST AU-11 / SOC2 CC7.4",
            "severity": "MEDIUM",
            "title": "Insufficient log retention",
            "detail": f"Logs retained for {log.get('log_retention_days', 'N/A')} days (need ≥90)",
            "fix": "Increase log_retention_days to at least 90",
        })

    if not log.get("centralized_logging", False):
        findings.append({
            "control": "NIST AU-6 / ISO A.12.4.1",
            "severity": "MEDIUM",
            "title": "No centralized logging",
            "detail": "Logs are not sent to a central SIEM",
            "fix": "Configure centralized logging (ELK, Splunk, etc.)",
        })

    # --- Data Protection (NIST SC, ISO A.10) ---
    data = config.get("data_protection", {})

    if not data.get("encryption_at_rest", False):
        findings.append({
            "control": "NIST SC-28 / ISO A.10.1.1 / SOC2 CC6.7",
            "severity": "HIGH",
            "title": "No encryption at rest",
            "detail": "Stored data is not encrypted",
            "fix": "Enable encryption at rest (LUKS, BitLocker, AWS KMS, etc.)",
        })

    if not data.get("backup_encrypted", False):
        findings.append({
            "control": "NIST CP-9 / ISO A.12.3.1",
            "severity": "MEDIUM",
            "title": "Backups not encrypted",
            "detail": "Backup data is stored unencrypted",
            "fix": "Enable encryption for all backups",
        })

    # --- Access Control (NIST AC, ISO A.9) ---
    ac = config.get("access_control", {})

    if not ac.get("rbac_enabled", False):
        findings.append({
            "control": "NIST AC-3 / ISO A.9.2.3 / SOC2 CC6.3",
            "severity": "HIGH",
            "title": "No role-based access control",
            "detail": "RBAC is not configured",
            "fix": "Implement RBAC with least privilege principle",
        })

    if ac.get("session_timeout_minutes", 0) == 0:
        findings.append({
            "control": "NIST AC-11 / CIS 5.4.5",
            "severity": "MEDIUM",
            "title": "No session timeout",
            "detail": "Sessions never expire automatically",
            "fix": "Set session_timeout_minutes to 15-30",
        })

    # --- Compliance Posture ---
    comp = config.get("compliance", {})

    if not comp.get("incident_response_plan", False):
        findings.append({
            "control": "NIST IR-1 / ISO A.16.1.1 / SOC2 CC7.3",
            "severity": "CRITICAL",
            "title": "No incident response plan",
            "detail": "No documented IR plan exists",
            "fix": "Create and test an incident response plan",
        })

    if not comp.get("security_training", False):
        findings.append({
            "control": "NIST AT-2 / ISO A.7.2.2 / SOC2 CC1.4",
            "severity": "MEDIUM",
            "title": "No security awareness training",
            "detail": "Staff have not received security training",
            "fix": "Implement regular security awareness training",
        })

    return findings


def _calculate_score(findings: list[dict]) -> int:
    """Calculate a compliance score out of 100."""
    severity_weights = {"CRITICAL": 15, "HIGH": 10, "MEDIUM": 5, "LOW": 2}
    total_penalty = sum(severity_weights.get(f["severity"], 0) for f in findings)
    return max(0, 100 - total_penalty)


# ---------------------------------------------------------------------------
# Main agent function
# ---------------------------------------------------------------------------

def run(config_path: str) -> dict:
    """
    Audit system configuration against security frameworks.

    Args:
        config_path: Path to YAML configuration file

    Returns:
        Dictionary with compliance findings, score, and AI recommendations
    """
    print_agent_header("POLICY CHECKER AGENT", "📜")

    # Load config
    with open(config_path, "r") as f:
        config = yaml.safe_load(f)

    hostname = config.get("system", {}).get("hostname", "Unknown")
    print(f"  🖥️  Auditing system: {hostname}")
    print(f"  📋 Frameworks: ISO 27001, NIST CSF, SOC 2, CIS Benchmarks")

    # Run policy checks
    findings = _check_policies(config)
    score = _calculate_score(findings)

    # Display findings
    severity_counts = {}
    for f_item in findings:
        sev = f_item["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        print_finding(sev, f'{f_item["title"]} [{f_item["control"]}]', f_item["detail"])

    print(f"\n  📊 Compliance Score: {score}/100")
    print(f"     CRITICAL: {severity_counts.get('CRITICAL', 0)}"
          f"  |  HIGH: {severity_counts.get('HIGH', 0)}"
          f"  |  MEDIUM: {severity_counts.get('MEDIUM', 0)}"
          f"  |  LOW: {severity_counts.get('LOW', 0)}")

    # AI-powered compliance report
    system_prompt = """You are a cybersecurity compliance auditor with expertise in
ISO 27001, NIST Cybersecurity Framework, SOC 2, and CIS Benchmarks.

Generate a compliance audit report that includes:
1. Executive summary with overall risk posture
2. Framework-by-framework gap analysis (ISO 27001, NIST, SOC 2)
3. Prioritized remediation roadmap (30/60/90 day plan)
4. Quick wins vs long-term improvements
5. Estimated effort and cost ranges for each fix

Use markdown formatting. Be specific and actionable."""

    prompt = f"""System configuration being audited:
{yaml.dump(config, default_flow_style=False)}

Policy check findings ({len(findings)} issues, score {score}/100):
{yaml.dump(findings, default_flow_style=False)}

Generate a comprehensive compliance audit report with remediation roadmap."""

    print("\n  🧠 Generating AI compliance report...")
    ai_report = call_llm(prompt, system_prompt)
    print_result(ai_report)

    return {
        "agent": "policy_checker",
        "system": hostname,
        "compliance_score": score,
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "findings": findings,
        "ai_report": ai_report,
    }
