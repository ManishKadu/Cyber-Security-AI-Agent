"""
main_v2.py - Upgraded Orchestrator with RAG + Token Optimization
=================================================================
This is the UPGRADED version of main.py that demonstrates:
  1. RAG-powered threat intelligence (ChromaDB)
  2. Token optimization (summarization, compression, skip logic)
  3. Cost tracking across all agents

Usage:
    python main_v2.py                     # Run all agents (upgraded)
    python main_v2.py --agent threat      # RAG-powered threat intel only
    python main_v2.py --optimize          # Enable all token optimizations
    python main_v2.py --save-report       # Save JSON report

    streamlit run dashboard/app.py        # Launch web dashboard
"""

import argparse
import json
import os
import sys
from datetime import datetime

from utils.display import print_banner, print_section, print_status, print_error, console
from utils.token_optimizer import (
    count_tokens_estimate,
    estimate_cost,
    summarize_logs_for_prompt,
    should_skip_llm_call,
)
from rich.panel import Panel
from rich.table import Table
from rich import box


def main():
    parser = argparse.ArgumentParser(description="Cyber Security AI Agent v2 (RAG + Optimization)")
    parser.add_argument("--agent", choices=["log", "threat", "vuln", "policy", "respond", "all"], default="all")
    parser.add_argument("--optimize", action="store_true", help="Enable all token optimizations")
    parser.add_argument("--save-report", action="store_true", help="Save report as JSON")
    parser.add_argument("--no-rag", action="store_true", help="Disable RAG for threat intel")
    args = parser.parse_args()

    print_banner()

    # Configuration display
    model = os.getenv("LLM_MODEL", "gpt-4o-mini")
    provider = os.getenv("LLM_PROVIDER", "openai")

    console.print(Panel(
        "[bold]System initialized (v2 — RAG + Optimization)[/bold]\n"
        f"  Time:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"  LLM:      {provider} / {model}\n"
        f"  RAG:      {'Disabled' if args.no_rag else 'ChromaDB + OpenAI embeddings'}\n"
        f"  Optimize: {'All optimizations ON' if args.optimize else 'Standard mode'}",
        title="⚙️  Configuration",
        box=box.ROUNDED,
        style="dim",
    ))

    all_results = {}
    total_cost_tracker = []

    try:
        # ---- Agent 1: Log Monitor (with token optimization) ----
        if args.agent in ["all", "log"]:
            print_section("PHASE 1 — LOG ANALYSIS")

            from agents.log_monitor import _rule_based_scan, _extract_ips
            from utils.llm import call_llm

            with open("data/sample_logs.txt", "r") as f:
                logs = f.read()

            findings = _rule_based_scan(logs)
            ips = _extract_ips(logs)

            print(f"  📄 {len(logs.splitlines())} log lines loaded")
            print(f"  🔍 Rule-based scan: {len(findings)} threats found")

            # Token optimization demo
            if args.optimize:
                if should_skip_llm_call(findings, threshold=0):
                    print_status("No findings — skipping AI call (saved ~1000 tokens)")
                    ai_analysis = "No threats found. AI analysis skipped for cost savings."
                else:
                    optimized = summarize_logs_for_prompt(logs, findings)
                    original_tokens = count_tokens_estimate(logs)
                    optimized_tokens = count_tokens_estimate(optimized)
                    print_status(f"Token optimization: {original_tokens} → {optimized_tokens} tokens ({round((1-optimized_tokens/original_tokens)*100)}% saved)")
                    ai_analysis = call_llm(
                        f"Analyze:\n{optimized}",
                        "Analyze logs. For each threat: severity, attack type, source, actions. Concise.",
                    )
            else:
                ai_analysis = call_llm(
                    f"Analyze these logs:\n{logs}\nFindings: {findings}\nIPs: {ips}",
                    "You are a cybersecurity log analyst. Identify threats with severity, attack type, source IP, actions.",
                )

            all_results["log_monitor"] = {"findings": findings, "ips": ips, "ai_analysis": ai_analysis}
            print_status("Log Monitor completed")

        # ---- Agent 2: Threat Intel (RAG-enhanced) ----
        if args.agent in ["all", "threat"]:
            print_section("PHASE 2 — THREAT INTELLIGENCE (RAG)")

            software_stack = ["apache 2.4", "openssh 8.9", "linux kernel 5.15", "curl"]

            if not args.no_rag:
                from agents.threat_intel_rag import run as run_threat_rag
                all_results["threat_intel"] = run_threat_rag(software_stack)
            else:
                from agents.threat_intel import run as run_threat
                all_results["threat_intel"] = run_threat(software_stack)

            print_status("Threat Intelligence completed")

        # ---- Agent 3: Vulnerability Scanner ----
        if args.agent in ["all", "vuln"]:
            print_section("PHASE 3 — VULNERABILITY SCANNING")
            from agents.vuln_scanner import run as run_vuln
            all_results["vuln_scanner"] = run_vuln(use_sample=True)
            print_status("Vulnerability Scanner completed")

        # ---- Agent 4: Policy Checker ----
        if args.agent in ["all", "policy"]:
            print_section("PHASE 4 — COMPLIANCE AUDIT")
            from agents.policy_checker import run as run_policy
            all_results["policy_checker"] = run_policy("data/system_config.yaml")
            print_status("Policy Checker completed")

        # ---- Agent 5: Incident Response ----
        if args.agent in ["all", "respond"]:
            print_section("PHASE 5 — INCIDENT RESPONSE")
            if not all_results:
                print_error("No findings. Run other agents first.")
            else:
                from agents.incident_response import run as run_ir
                all_results["incident_response"] = run_ir(all_results)
                print_status("Incident Response completed")

        # ---- Summary ----
        print_section("EXECUTION COMPLETE")

        # Cost estimation table
        table = Table(title="💰 Estimated Token Usage & Cost", box=box.ROUNDED)
        table.add_column("Agent", style="cyan")
        table.add_column("Input Tokens", justify="right")
        table.add_column("Output Tokens", justify="right")
        table.add_column("Cost", justify="right", style="green")

        total_in = 0
        total_out = 0
        total_cost = 0

        for agent_name, result in all_results.items():
            ai_text = result.get("ai_analysis", result.get("plan", result.get("ai_report", "")))
            in_tokens = count_tokens_estimate(str(result))
            out_tokens = count_tokens_estimate(str(ai_text))
            cost_info = estimate_cost(in_tokens, out_tokens, model)

            total_in += in_tokens
            total_out += out_tokens
            total_cost += cost_info["total_cost"]

            table.add_row(
                agent_name,
                f"{in_tokens:,}",
                f"{out_tokens:,}",
                f"${cost_info['total_cost']:.4f}",
            )

        table.add_row("", "", "", "", style="dim")
        table.add_row(
            "[bold]TOTAL[/bold]",
            f"[bold]{total_in:,}[/bold]",
            f"[bold]{total_out:,}[/bold]",
            f"[bold]${total_cost:.4f}[/bold]",
        )
        console.print(table)

        console.print(Panel(
            f"[bold green]✓ {len(all_results)} agents completed[/bold green]\n"
            f"  Total cost: ${total_cost:.4f} ({model})",
            title="📊 Summary",
            box=box.ROUNDED,
        ))

        # Save report
        if args.save_report:
            os.makedirs("reports", exist_ok=True)
            path = f"reports/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(path, "w") as f:
                json.dump(all_results, f, indent=2, default=str)
            print_status(f"Report saved to {path}")

    except Exception as e:
        print_error(f"Error: {e}")
        console.print_exception()
        sys.exit(1)


if __name__ == "__main__":
    main()
