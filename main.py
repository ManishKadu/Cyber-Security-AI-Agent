"""
main.py - Cyber Security AI Agent Orchestrator
===============================================
Runs all 5 security agents in sequence, collects findings,
and generates a unified incident response plan.

Usage:
    python main.py                    # Run all agents with sample data
    python main.py --agent log        # Run only the log monitor
    python main.py --agent threat     # Run only threat intelligence
    python main.py --agent vuln       # Run only vulnerability scanner
    python main.py --agent policy     # Run only policy checker
    python main.py --agent respond    # Run only incident response (needs other agent data)
"""

import argparse
import json
import os
import sys
from datetime import datetime

from utils.display import print_banner, print_section, print_status, print_error, console
from rich.panel import Panel
from rich import box


def run_log_monitor():
    from agents.log_monitor import run
    return run("data/sample_logs.txt")


def run_threat_intel():
    from agents.threat_intel import run
    # Sample software stack — customize for your environment
    stack = ["apache 2.4", "openssl 3.0", "linux kernel 5.15", "openssh 8.9"]
    return run(stack)


def run_vuln_scanner():
    from agents.vuln_scanner import run
    return run(use_sample=True)


def run_policy_checker():
    from agents.policy_checker import run
    return run("data/system_config.yaml")


def run_incident_response(findings):
    from agents.incident_response import run
    return run(findings)


def main():
    parser = argparse.ArgumentParser(description="Cyber Security AI Agent System")
    parser.add_argument(
        "--agent",
        choices=["log", "threat", "vuln", "policy", "respond", "all"],
        default="all",
        help="Which agent to run (default: all)",
    )
    parser.add_argument(
        "--save-report",
        action="store_true",
        help="Save the full report as JSON",
    )
    args = parser.parse_args()

    print_banner()

    console.print(Panel(
        "[bold]System initialized[/bold]\n"
        f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"  Mode: {'Full Scan' if args.agent == 'all' else args.agent.upper() + ' Agent Only'}\n"
        f"  LLM:  {os.getenv('LLM_PROVIDER', 'openai')} / {os.getenv('LLM_MODEL', 'gpt-4o-mini')}",
        title="⚙️  Configuration",
        box=box.ROUNDED,
        style="dim",
    ))

    all_results = {}

    try:
        # ---- Agent 1: Log Monitor ----
        if args.agent in ["all", "log"]:
            print_section("PHASE 1 — LOG ANALYSIS")
            all_results["log_monitor"] = run_log_monitor()
            print_status("Log Monitor Agent completed")

        # ---- Agent 2: Threat Intelligence ----
        if args.agent in ["all", "threat"]:
            print_section("PHASE 2 — THREAT INTELLIGENCE")
            all_results["threat_intel"] = run_threat_intel()
            print_status("Threat Intelligence Agent completed")

        # ---- Agent 3: Vulnerability Scanner ----
        if args.agent in ["all", "vuln"]:
            print_section("PHASE 3 — VULNERABILITY SCANNING")
            all_results["vuln_scanner"] = run_vuln_scanner()
            print_status("Vulnerability Scanner Agent completed")

        # ---- Agent 4: Policy Checker ----
        if args.agent in ["all", "policy"]:
            print_section("PHASE 4 — COMPLIANCE AUDIT")
            all_results["policy_checker"] = run_policy_checker()
            print_status("Policy Checker Agent completed")

        # ---- Agent 5: Incident Response ----
        if args.agent in ["all", "respond"]:
            print_section("PHASE 5 — INCIDENT RESPONSE PLANNING")
            if not all_results:
                print_error("No findings to respond to. Run other agents first.")
                print("  Tip: Use 'python main.py' to run all agents together.")
            else:
                all_results["incident_response"] = run_incident_response(all_results)
                print_status("Incident Response Agent completed")

        # ---- Summary ----
        print_section("EXECUTION COMPLETE")
        console.print(Panel(
            f"[bold green]✓ {len(all_results)} agents completed successfully[/bold green]\n"
            f"  Agents run: {', '.join(all_results.keys())}",
            title="📊 Summary",
            box=box.ROUNDED,
        ))

        # ---- Save report ----
        if args.save_report:
            report_path = f"reports/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            os.makedirs("reports", exist_ok=True)
            with open(report_path, "w") as f:
                json.dump(all_results, f, indent=2, default=str)
            print_status(f"Report saved to {report_path}")

    except Exception as e:
        print_error(f"Error: {e}")
        console.print_exception()
        sys.exit(1)


if __name__ == "__main__":
    main()
