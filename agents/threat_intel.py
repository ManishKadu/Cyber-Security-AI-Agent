"""
agents/threat_intel.py - Threat Intelligence Agent
===================================================
Looks up known CVEs from the National Vulnerability Database (NVD),
checks if your software stack is affected, and provides risk summaries.
"""

import os
import json
import requests
from utils.llm import call_llm
from utils.display import print_agent_header, print_finding, print_result


NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _search_nvd(keyword: str, max_results: int = 5) -> list[dict]:
    """
    Search the NVD (National Vulnerability Database) for CVEs.

    Args:
        keyword: Software name or keyword (e.g. "apache", "openssl")
        max_results: Maximum CVEs to return

    Returns:
        List of CVE dictionaries with id, description, severity, score
    """
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results,
    }

    api_key = os.getenv("NVD_API_KEY")
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    try:
        resp = requests.get(NVD_API_BASE, params=params, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        print(f"  ⚠️  NVD API error: {e}")
        print("  ℹ️  Falling back to AI-based threat intelligence")
        return []

    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "N/A")

        # Get description
        descriptions = cve.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description")

        # Get CVSS score
        metrics = cve.get("metrics", {})
        score = "N/A"
        severity = "UNKNOWN"

        for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version_key in metrics:
                cvss_data = metrics[version_key][0].get("cvssData", {})
                score = cvss_data.get("baseScore", "N/A")
                severity = cvss_data.get("baseSeverity", "UNKNOWN")
                break

        results.append({
            "cve_id": cve_id,
            "description": desc[:200],
            "score": score,
            "severity": severity,
        })

    return results


def run(software_stack: list[str]) -> dict:
    """
    Check a software stack against known vulnerabilities.

    Args:
        software_stack: List of software names, e.g. ["apache 2.4", "openssl 3.0", "nginx"]

    Returns:
        Dictionary with CVE findings and AI risk assessment
    """
    print_agent_header("THREAT INTELLIGENCE AGENT", "🕵️")

    all_cves = {}
    total_found = 0

    for software in software_stack:
        print(f"\n  🔎 Searching NVD for: {software}")
        cves = _search_nvd(software)

        if cves:
            all_cves[software] = cves
            total_found += len(cves)
            for cve in cves:
                print_finding(
                    cve["severity"] if cve["severity"] != "UNKNOWN" else "MEDIUM",
                    f'{cve["cve_id"]} (Score: {cve["score"]})',
                    cve["description"][:100] + "...",
                )
        else:
            print(f"     No CVEs found (or API unavailable)")

    # AI-powered risk assessment
    system_prompt = """You are a cybersecurity threat intelligence analyst.
Analyze the CVE data and software stack to provide:
1. Overall risk rating for this environment
2. Which CVEs are most critical and why
3. Whether any CVEs can be chained together for a bigger attack
4. Prioritized remediation steps
5. Threat actor groups known to exploit these CVEs (if any)

Be concise. Use markdown formatting."""

    prompt = f"""Software stack being assessed:
{json.dumps(software_stack, indent=2)}

CVE findings from NVD:
{json.dumps(all_cves, indent=2, default=str)}

Provide a threat intelligence briefing for this environment."""

    print("\n  🧠 Generating AI threat intelligence briefing...")
    ai_analysis = call_llm(prompt, system_prompt)
    print_result(ai_analysis)

    return {
        "agent": "threat_intel",
        "software_stack": software_stack,
        "total_cves_found": total_found,
        "cve_details": all_cves,
        "ai_analysis": ai_analysis,
    }
