"""
agents/incident_response.py - Incident Response Agent
======================================================
Takes findings from other agents and creates structured,
step-by-step incident response plans using NIST framework.
"""

import json
from datetime import datetime
from utils.llm import call_llm
from utils.display import print_agent_header, print_result


NIST_IR_PHASES = [
    "1. Preparation",
    "2. Detection & Analysis",
    "3. Containment",
    "4. Eradication",
    "5. Recovery",
    "6. Post-Incident Activity / Lessons Learned",
]


def run(findings: dict) -> dict:
    """
    Generate an incident response plan from security findings.

    Args:
        findings: Combined results dict from other agents,
                  e.g. {"log_monitor": {...}, "vuln_scanner": {...}, ...}

    Returns:
        Dictionary with the incident response plan
    """
    print_agent_header("INCIDENT RESPONSE AGENT", "🚨")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"  📅 Incident Response Plan generated at: {timestamp}")
    print(f"  📊 Processing findings from {len(findings)} agents")
    print(f"  📋 Using NIST SP 800-61 Incident Response Framework")

    system_prompt = """You are a senior incident response manager following the
NIST SP 800-61 Computer Security Incident Handling Guide. Generate a comprehensive
incident response plan that includes:

## Structure your response with these NIST phases:

### 1. PREPARATION
- Team roles and responsibilities
- Tools and resources needed
- Communication plan

### 2. DETECTION & ANALYSIS
- Summary of detected threats (from provided findings)
- Threat severity classification
- Attack vector analysis
- Indicators of Compromise (IoCs)

### 3. CONTAINMENT
- Short-term containment actions (first 1 hour)
- Long-term containment strategy
- Evidence preservation steps

### 4. ERADICATION
- Root cause removal steps
- System hardening actions
- Patch/update requirements

### 5. RECOVERY
- System restoration steps
- Monitoring plan post-recovery
- Validation/testing steps

### 6. POST-INCIDENT ACTIVITY
- Lessons learned
- Process improvements
- Documentation requirements
- Metrics to track

Also provide:
- **Estimated timeline** for the full response
- **Escalation matrix** (when to involve management, legal, law enforcement)
- **Runbook commands** where applicable (firewall rules, user lockouts, etc.)

Use markdown formatting. Be specific and actionable."""

    prompt = f"""Generate an incident response plan based on these security findings:

TIMESTAMP: {timestamp}

FINDINGS FROM SECURITY AGENTS:
{json.dumps(findings, indent=2, default=str)}

Create a detailed, actionable incident response plan following NIST SP 800-61.
Include specific commands and steps the security team should execute."""

    print("\n  🧠 Generating incident response plan...")
    ai_plan = call_llm(prompt, system_prompt)
    print_result(ai_plan)

    return {
        "agent": "incident_response",
        "timestamp": timestamp,
        "framework": "NIST SP 800-61",
        "phases": NIST_IR_PHASES,
        "plan": ai_plan,
        "input_findings_count": len(findings),
    }
