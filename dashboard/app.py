"""
dashboard/app.py - Streamlit Security Dashboard
=================================================
Beautiful web UI that runs all 5 agents and displays results
with charts, metrics, and interactive controls.

Run with:
    streamlit run dashboard/app.py
"""

import sys
import os
import json
import time

# Add parent directory to path so imports work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st
import yaml

# ---------------------------------------------------------------------------
# Page Configuration
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="CyberSec AI Agent Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Custom CSS for professional look
# ---------------------------------------------------------------------------

st.markdown("""
<style>
    .stMetricValue { font-size: 28px !important; }
    .severity-critical { color: #E24B4A; font-weight: bold; }
    .severity-high { color: #D85A30; font-weight: bold; }
    .severity-medium { color: #BA7517; font-weight: bold; }
    .severity-low { color: #378ADD; }
    .agent-card {
        padding: 1rem;
        border-radius: 8px;
        border: 1px solid #e0e0e0;
        margin-bottom: 1rem;
    }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    st.title("🛡️ CyberSec AI Agent")
    st.markdown("---")

    # LLM Configuration
    st.subheader("⚙️ Configuration")
    provider = st.selectbox("LLM Provider", ["openai", "anthropic"])
    model_options = {
        "openai": ["gpt-4o-mini", "gpt-4o"],
        "anthropic": ["claude-sonnet-4-20250514", "claude-haiku-4-5-20251001"],
    }
    model = st.selectbox("Model", model_options[provider])

    st.markdown("---")

    # Agent Selection
    st.subheader("🤖 Agents to Run")
    run_log = st.checkbox("📋 Log Monitor", value=True)
    run_threat = st.checkbox("🕵️ Threat Intelligence (RAG)", value=True)
    run_vuln = st.checkbox("🔓 Vulnerability Scanner", value=True)
    run_policy = st.checkbox("📜 Policy Checker", value=True)
    run_incident = st.checkbox("🚨 Incident Response", value=True)

    st.markdown("---")

    # Token Optimization
    st.subheader("💰 Token Optimization")
    opt_summarize = st.checkbox("Summarize logs before sending", value=False)
    opt_short_prompt = st.checkbox("Use compressed prompts", value=False)
    opt_skip_empty = st.checkbox("Skip AI if no findings", value=False)
    max_output = st.slider("Max output tokens", 256, 4096, 2048, 256)

    st.markdown("---")

    # RAG Settings
    st.subheader("📚 RAG Settings")
    rag_enabled = st.checkbox("Enable RAG for Threat Intel", value=True)
    rag_top_k = st.slider("Top K results per query", 1, 10, 3)

    st.markdown("---")
    run_button = st.button("🚀 Run Security Scan", type="primary", use_container_width=True)


# ---------------------------------------------------------------------------
# Main Content
# ---------------------------------------------------------------------------

st.title("🛡️ Cybersecurity AI Agent Dashboard")
st.caption("Multi-agent system with RAG, token optimization, and real-time analysis")

# Top metrics row (placeholder until scan runs)
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Agents Active", f"{sum([run_log, run_threat, run_vuln, run_policy, run_incident])}/5")
with col2:
    st.metric("RAG Status", "Enabled" if rag_enabled else "Disabled")
with col3:
    st.metric("Model", model.split("-")[0].upper() if "-" in model else model)
with col4:
    st.metric("Max Tokens", f"{max_output:,}")


# ---------------------------------------------------------------------------
# Run Scan
# ---------------------------------------------------------------------------

if run_button:
    # Set environment variables
    os.environ["LLM_PROVIDER"] = provider
    os.environ["LLM_MODEL"] = model

    all_results = {}
    total_findings = 0

    # ---- Agent 1: Log Monitor ----
    if run_log:
        with st.status("📋 Running Log Monitor Agent...", expanded=True) as status:
            try:
                from agents.log_monitor import _rule_based_scan, _extract_ips

                log_path = "data/sample_logs.txt"
                with open(log_path, "r") as f:
                    logs = f.read()

                st.write(f"Loaded {len(logs.splitlines())} log lines")
                findings = _rule_based_scan(logs)
                ips = _extract_ips(logs)

                # Display findings
                for f_item in findings:
                    severity = f_item["severity"]
                    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(severity, "⚪")
                    st.write(f"{icon} **{severity}** — {f_item['rule']}: {f_item['description']}")

                if ips:
                    st.write("**Suspicious IPs:**")
                    for ip, count in ips.items():
                        st.write(f"  • `{ip}` — {count} failed attempts")

                # Token optimization: summarize if enabled
                if opt_summarize:
                    from utils.token_optimizer import summarize_logs_for_prompt
                    optimized = summarize_logs_for_prompt(logs, findings)
                    st.info(f"📊 Token optimization: {len(logs)} chars → {len(optimized)} chars ({round((1-len(optimized)/len(logs))*100)}% reduction)")

                # Skip LLM if no findings and optimization enabled
                if opt_skip_empty and len(findings) == 0:
                    st.success("✅ No threats found — skipping AI analysis (token savings!)")
                    ai_analysis = "No threats detected by rule-based scan. AI analysis skipped."
                else:
                    from utils.llm import call_llm

                    system_prompt = "Analyze logs for security threats. For each: severity, attack type, source IP, actions. Be concise."
                    prompt_data = optimized if opt_summarize else logs

                    if opt_short_prompt:
                        from utils.token_optimizer import compress_system_prompt
                        system_prompt = compress_system_prompt(system_prompt)

                    st.write("🧠 Running AI analysis...")
                    ai_analysis = call_llm(
                        f"Analyze these logs:\n{prompt_data}\n\nFindings: {findings}",
                        system_prompt,
                    )

                all_results["log_monitor"] = {
                    "findings": findings,
                    "suspicious_ips": ips,
                    "ai_analysis": ai_analysis if 'ai_analysis' in dir() else "Skipped",
                }
                total_findings += len(findings)
                status.update(label=f"📋 Log Monitor — {len(findings)} threats found", state="complete")

            except Exception as e:
                status.update(label=f"📋 Log Monitor — Error: {e}", state="error")
                st.error(str(e))

    # ---- Agent 2: Threat Intel (RAG) ----
    if run_threat:
        with st.status("🕵️ Running Threat Intelligence Agent...", expanded=True) as status:
            try:
                software_stack = ["apache 2.4", "openssh 8.9", "linux kernel 5.15", "curl"]

                if rag_enabled:
                    from rag.cve_knowledge_base import CVEKnowledgeBase

                    kb = CVEKnowledgeBase()
                    indexed = kb.index_cves()
                    st.write(f"📚 ChromaDB: {indexed} CVEs in knowledge base")

                    for sw in software_stack:
                        matches = kb.search(sw, top_k=rag_top_k)
                        if matches:
                            st.write(f"**{sw}** — {len(matches)} CVEs found:")
                            for m in matches:
                                meta = m["metadata"]
                                st.write(f"  🔹 `{m['cve_id']}` — Score: {meta.get('score', '?')}, Similarity: {m['similarity_score']:.0%}")

                    rag_context = kb.get_rag_context(software_stack, top_k=rag_top_k)
                    st.write("🧠 Running RAG-augmented AI analysis...")

                    from utils.llm import call_llm
                    ai_analysis = call_llm(
                        f"Software: {software_stack}\n\n{rag_context}\n\nProvide threat briefing.",
                        "Analyze CVEs for this software stack. Prioritize by risk. Be concise.",
                    )
                else:
                    from agents.threat_intel import run as run_threat_fn
                    result = run_threat_fn(software_stack)
                    ai_analysis = result.get("ai_analysis", "")

                all_results["threat_intel"] = {"ai_analysis": ai_analysis}
                status.update(label="🕵️ Threat Intelligence — Complete", state="complete")

            except Exception as e:
                status.update(label=f"🕵️ Threat Intel — Error: {e}", state="error")
                st.error(str(e))

    # ---- Agent 3: Vulnerability Scanner ----
    if run_vuln:
        with st.status("🔓 Running Vulnerability Scanner...", expanded=True) as status:
            try:
                from agents.vuln_scanner import _scan_code, SAMPLE_VULNERABLE_CODE

                findings = _scan_code(SAMPLE_VULNERABLE_CODE)
                st.write(f"Found {len(findings)} vulnerabilities in sample code:")

                for f_item in findings:
                    severity = f_item["severity"]
                    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(severity, "⚪")
                    st.write(f"{icon} **{f_item['vulnerability']}** ({f_item['cwe']}) — {f_item['description']}")

                from utils.llm import call_llm
                st.write("🧠 Running AI code review...")
                ai_analysis = call_llm(
                    f"Review this code:\n```python\n{SAMPLE_VULNERABLE_CODE}\n```\nFindings: {[f['vulnerability'] for f in findings]}\nProvide fixed code.",
                    "You are a security code reviewer. Find OWASP Top 10 vulns, show fixed code. Be concise.",
                )

                all_results["vuln_scanner"] = {"findings": findings, "ai_analysis": ai_analysis}
                total_findings += len(findings)
                status.update(label=f"🔓 Vulnerability Scanner — {len(findings)} vulns found", state="complete")

            except Exception as e:
                status.update(label=f"🔓 Vuln Scanner — Error: {e}", state="error")
                st.error(str(e))

    # ---- Agent 4: Policy Checker ----
    if run_policy:
        with st.status("📜 Running Policy Checker...", expanded=True) as status:
            try:
                from agents.policy_checker import _check_policies, _calculate_score

                with open("data/system_config.yaml", "r") as f:
                    config = yaml.safe_load(f)

                findings = _check_policies(config)
                score = _calculate_score(findings)

                st.write(f"**Compliance Score: {score}/100**")

                severity_counts = {}
                for f_item in findings:
                    sev = f_item["severity"]
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
                    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(sev, "⚪")
                    st.write(f"{icon} **{f_item['title']}** [{f_item['control']}]")

                from utils.llm import call_llm
                st.write("🧠 Generating compliance report...")
                ai_report = call_llm(
                    f"Config: {yaml.dump(config)}\nFindings ({len(findings)} issues, score {score}/100): {yaml.dump(findings)}\nGenerate 30/60/90 day remediation plan.",
                    "Compliance auditor for ISO 27001, NIST, SOC2. Be concise and actionable.",
                )

                all_results["policy_checker"] = {
                    "score": score,
                    "findings": findings,
                    "severity_counts": severity_counts,
                    "ai_report": ai_report,
                }
                total_findings += len(findings)
                status.update(label=f"📜 Policy Checker — Score: {score}/100", state="complete")

            except Exception as e:
                status.update(label=f"📜 Policy Checker — Error: {e}", state="error")
                st.error(str(e))

    # ---- Agent 5: Incident Response ----
    if run_incident and all_results:
        with st.status("🚨 Generating Incident Response Plan...", expanded=True) as status:
            try:
                from utils.llm import call_llm

                st.write("🧠 Synthesizing all findings into response plan...")
                # Summarize findings to save tokens
                summary = json.dumps(
                    {k: {"finding_count": len(v.get("findings", []))} for k, v in all_results.items()},
                    default=str,
                )
                ai_plan = call_llm(
                    f"Generate NIST SP 800-61 incident response plan.\nFindings summary: {summary}\nInclude: containment, eradication, recovery, lessons learned. Include specific commands.",
                    "Incident response manager following NIST SP 800-61. Be specific and actionable.",
                )

                all_results["incident_response"] = {"plan": ai_plan}
                status.update(label="🚨 Incident Response — Plan Generated", state="complete")

            except Exception as e:
                status.update(label=f"🚨 Incident Response — Error: {e}", state="error")
                st.error(str(e))

    # ---------------------------------------------------------------------------
    # Results Display
    # ---------------------------------------------------------------------------

    st.markdown("---")
    st.header("📊 Scan Results")

    # Updated metrics
    rcol1, rcol2, rcol3, rcol4 = st.columns(4)
    with rcol1:
        st.metric("Total Findings", total_findings)
    with rcol2:
        st.metric("Agents Completed", len(all_results))
    with rcol3:
        policy_score = all_results.get("policy_checker", {}).get("score", "N/A")
        st.metric("Compliance Score", f"{policy_score}/100" if isinstance(policy_score, int) else policy_score)
    with rcol4:
        st.metric("RAG CVEs Retrieved", "Yes" if rag_enabled else "No")

    # Tabbed results
    tabs = st.tabs(["📋 Log Monitor", "🕵️ Threat Intel", "🔓 Vuln Scanner", "📜 Policy Checker", "🚨 Incident Response"])

    with tabs[0]:
        if "log_monitor" in all_results:
            data = all_results["log_monitor"]
            st.subheader("AI Analysis")
            st.markdown(data.get("ai_analysis", "Not available"))
        else:
            st.info("Log Monitor was not run in this scan.")

    with tabs[1]:
        if "threat_intel" in all_results:
            st.subheader("AI Threat Briefing")
            st.markdown(all_results["threat_intel"].get("ai_analysis", "Not available"))
        else:
            st.info("Threat Intelligence was not run in this scan.")

    with tabs[2]:
        if "vuln_scanner" in all_results:
            st.subheader("AI Code Review & Fixes")
            st.markdown(all_results["vuln_scanner"].get("ai_analysis", "Not available"))
        else:
            st.info("Vulnerability Scanner was not run in this scan.")

    with tabs[3]:
        if "policy_checker" in all_results:
            data = all_results["policy_checker"]

            # Severity chart
            if "severity_counts" in data:
                st.subheader("Findings by Severity")
                chart_data = data["severity_counts"]
                st.bar_chart(chart_data)

            st.subheader("AI Compliance Report")
            st.markdown(data.get("ai_report", "Not available"))
        else:
            st.info("Policy Checker was not run in this scan.")

    with tabs[4]:
        if "incident_response" in all_results:
            st.subheader("NIST SP 800-61 Incident Response Plan")
            st.markdown(all_results["incident_response"].get("plan", "Not available"))
        else:
            st.info("Incident Response was not run in this scan.")

    # Export option
    st.markdown("---")
    if st.button("📥 Export Full Report as JSON"):
        report_json = json.dumps(all_results, indent=2, default=str)
        st.download_button(
            "Download Report",
            report_json,
            file_name="cybersec_report.json",
            mime="application/json",
        )

else:
    # Landing state
    st.info("👈 Configure settings in the sidebar and click **Run Security Scan** to start.")

    # Show architecture overview
    st.markdown("---")
    st.subheader("System Architecture")

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("""
        **🤖 5 AI Agents**
        - Log Monitor
        - Threat Intelligence (RAG)
        - Vulnerability Scanner
        - Policy Checker
        - Incident Response
        """)
    with col2:
        st.markdown("""
        **🧠 AI Features**
        - RAG with ChromaDB
        - Token Optimization
        - Multi-model Support
        - Hybrid Analysis
        """)
    with col3:
        st.markdown("""
        **📋 Frameworks**
        - MITRE ATT&CK
        - OWASP Top 10
        - NIST SP 800-61
        - ISO 27001 / SOC 2
        """)
