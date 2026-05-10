
#  Cyber Security AI Agent

A multi-agent AI-powered cybersecurity system that monitors logs, detects threats, scans for vulnerabilities, audits compliance, and generates incident response plans — all using a hybrid approach of rule-based detection and LLM-powered analysis.

## What This Project Does

This system runs **5 specialized AI agents** in sequence, each responsible for a different aspect of cybersecurity. Each agent first performs fast, deterministic analysis using regex pattern matching, then sends findings to an LLM (OpenAI GPT ) for deeper contextual analysis that rules alone can't catch.

```
┌─────────────────────────────────────────────────────────┐
│                    main.py / main_v2.py                  │
│                      (Orchestrator)                      │
└────────┬──────┬──────┬──────┬──────┬────────────────────┘
         │      │      │      │      │
         ▼      ▼      ▼      ▼      ▼
      ┌──────┐┌──────┐┌──────┐┌──────┐┌──────────┐
      │ Log  ││Threat││ Vuln ││Policy││ Incident │
      │Monitor││Intel ││Scan  ││Check ││ Response │
      └──┬───┘└──┬───┘└──┬───┘└──┬───┘└────┬─────┘
         │       │       │       │         │
      Log     NVD API  Code    YAML    All Findings
      Files  + ChromaDB Review  Config  → IR Plan
```

## The 5 Agents

### Agent 1: Log Monitor
Reads system and network logs (SSH, Apache, firewall) to detect brute force attacks, SQL injection attempts, port scans, suspicious cron jobs, and directory enumeration. Uses 7 regex patterns for instant detection, then AI for correlation analysis and MITRE ATT&CK mapping.

### Agent 2: Threat Intelligence (RAG-Enhanced)
Takes your software stack  checks for known vulnerabilities. The **original version** queries the NVD (National Vulnerability Database) API. The **RAG-enhanced version** uses ChromaDB vector search with OpenAI embeddings to find semantically relevant CVEs — meaning "openssh" also finds CVEs about SSH backdoors and sshd race conditions, not just exact keyword matches.

### Agent 3: Vulnerability Scanner
Performs static code analysis for OWASP Top 10 vulnerabilities: SQL injection, XSS, hardcoded secrets, insecure deserialization, weak cryptography, SSRF, and debug mode. Includes a deliberately vulnerable Flask app as demo code. AI provides fixed code snippets for each finding.

### Agent 4: Policy Checker
Audits system configuration (YAML) against four compliance frameworks: **ISO 27001**, **NIST Cybersecurity Framework**, **SOC 2**, and **CIS Benchmarks**. Checks 18 controls covering authentication, network security, logging, data protection, and access control. Calculates a compliance score out of 100 and generates a 30/60/90 day remediation roadmap.

### Agent 5: Incident Response
Collects all findings from Agents 1-4 and generates a structured incident response plan following the **NIST SP 800-61** framework with 6 phases: Preparation, Detection & Analysis, Containment, Eradication, Recovery, and Lessons Learned. Includes specific commands, timelines, and escalation steps.

## Key Features

### RAG (Retrieval-Augmented Generation)
The threat intelligence agent uses ChromaDB to store CVE data as vector embeddings. When you search for software, it performs semantic similarity search — finding relevant vulnerabilities by meaning, not just keywords. This grounds the LLM's analysis in real data instead of relying on potentially outdated training knowledge.

```
CVE descriptions → OpenAI embeddings (1536 dims) → ChromaDB → Similarity search → LLM prompt
```

### Token Optimization
Five techniques to reduce API costs
- **Log summarization** — send only anomalous lines, not all logs
- **Prompt compression** — remove filler words from system prompts
- **Conditional AI calls** — skip LLM when regex finds nothing
- **Output limiting** — cap max_tokens to prevent runaway responses
- **Model selection** — use GPT-4o-mini for simple tasks

### Streamlit Dashboard
Web-based UI with sidebar controls for model selection, agent toggles, RAG settings, and optimization switches. Results display in tabs with severity badges, compliance charts, and JSON export.

### Multi-Provider LLM Support
Swap between OpenAI and Anthropic by changing one line in `.env`. The `utils/llm.py` abstraction layer means zero code changes when switching providers.

## Project Structure

```
cybersec-ai-agent/
├── agents/
│   ├── log_monitor.py          # Regex + AI log analysis
│   ├── threat_intel.py         # NVD API integration
│   ├── threat_intel_rag.py     # RAG-enhanced version (ChromaDB)
│   ├── vuln_scanner.py         # OWASP Top 10 code scanning
│   ├── policy_checker.py       # ISO/NIST/SOC2/CIS audit
│   └── incident_response.py   # NIST SP 800-61 response plans
├── rag/
│   └── cve_knowledge_base.py   # ChromaDB vector store + embeddings
├── utils/
│   ├── llm.py                  # OpenAI/Anthropic abstraction
│   ├── token_optimizer.py      # Cost reduction utilities
│   └── display.py              # Rich terminal output
├── dashboard/
│   └── app.py                  # Streamlit web interface
├── data/
│   ├── sample_logs.txt         # Realistic attack logs (demo)
│   └── system_config.yaml      # Intentionally weak config (demo)
├── main.py                     # Original orchestrator
├── main_v2.py                  # Upgraded: RAG + token optimization
├── requirements.txt
└── .env                        # API keys (not committed)
```

## Quick Start

### 1. Clone and setup
```bash
git clone https://github.com/YOUR_USERNAME/cybersec-ai-agent.git
cd cybersec-ai-agent
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure API key
```bash
cp .env.example .env
# Edit .env with your OpenAI or Anthropic API key
```

### 3. Run
```bash
# Terminal — all 5 agents
python main.py

# Terminal — with RAG + token optimization
python main_v2.py --optimize

# Web dashboard
streamlit run dashboard/app.py

# Individual agents
python main.py --agent log
python main.py --agent threat
python main.py --agent vuln
python main.py --agent policy
```

## Requirements

- Python 3.10+
- An API key from [OpenAI]

## Tech Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| LLM | OpenAI GPT-4o-mini / Anthropic Claude | AI-powered analysis |
| Vector DB | ChromaDB | RAG embedding storage and search |
| Embeddings | OpenAI text-embedding-3-small | Convert text to vectors |
| Threat Data | NVD REST API | Real CVE lookups |
| Dashboard | Streamlit | Web-based UI |
| Terminal UI | Rich | Colored terminal output |
| Config | python-dotenv + PyYAML | Environment and config management |

## Security Frameworks Referenced

- **MITRE ATT&CK** — attack technique classification (Log Monitor)
- **OWASP Top 10** — web application vulnerabilities (Vuln Scanner)
- **NIST SP 800-61** — incident response handling (Incident Response)
- **NIST CSF** — cybersecurity framework controls (Policy Checker)
- **ISO 27001** — information security management (Policy Checker)
- **SOC 2** — service organization controls (Policy Checker)
- **CIS Benchmarks** — configuration security standards (Policy Checker)

## How It Works (Technical Detail)

Each agent follows the same 5-step pattern:

1. **Load input** — read log file, code, YAML config, or software list
2. **Rule-based scan** — run regex patterns for known attack signatures (instant, deterministic, free)
3. **Build prompt** — concatenate system_prompt + data + rule findings into one string
4. **Call LLM** — send to OpenAI or Anthropic via their Python SDK (single API call)
5. **Return results** — findings dict + AI analysis text → passed to orchestrator

The RAG version (Agent 2) adds an additional step between 1 and 2: query ChromaDB for semantically similar CVEs and inject them into the prompt.


## Limitations & Future Work

This is an intentional simplifications:

- **Static data** — reads files, not live log streams. Production would use Kafka/Fluentd.
- **Sequential execution** — agents run in fixed order. LangGraph could add dynamic routing.
- **No MCP integration** — all data is local. MCP would connect to live SIEM, cloud, and ticketing systems.
- **Sample CVE data** — RAG uses 15 curated CVEs. Production would index the full NVD (200K+ CVEs).

