"""
agents/threat_intel_rag.py - RAG-Powered Threat Intelligence Agent
===================================================================
UPGRADED version that uses ChromaDB vector search instead of
(or alongside) live NVD API calls.

BEFORE (original):  software name → NVD API → raw results → LLM
AFTER  (this file): software name → ChromaDB semantic search → enriched context → LLM

The LLM now gets REAL CVE data grounded in our knowledge base,
instead of relying on its training data (which may be outdated).
"""

import json
from utils.llm import call_llm
from utils.display import print_agent_header, print_finding, print_result, print_status
from rag.cve_knowledge_base import CVEKnowledgeBase


def run(software_stack: list[str], use_rag: bool = True) -> dict:
    """
    Check a software stack against known vulnerabilities using RAG.

    Args:
        software_stack: e.g. ["apache 2.4", "openssh 8.9", "linux kernel 5.15"]
        use_rag: If True, use ChromaDB. If False, fall back to original behavior.

    Returns:
        Dictionary with findings, RAG context, and AI analysis
    """
    print_agent_header("THREAT INTELLIGENCE AGENT (RAG-ENHANCED)", "🕵️")

    # ---- Step 1: Initialize RAG knowledge base ----
    kb = CVEKnowledgeBase()
    kb.index_cves()  # Only indexes on first run; cached after that

    stats = kb.get_stats()
    print(f"  📚 Knowledge base: {stats['count']} CVEs indexed")
    print(f"  🧮 Embedding model: {stats.get('embedding_model', 'N/A')}")

    # ---- Step 2: Semantic search for each software ----
    all_matches = {}
    total_found = 0

    for software in software_stack:
        print(f"\n  🔎 RAG search for: {software}")
        matches = kb.search(software, top_k=3)

        if matches:
            all_matches[software] = matches
            total_found += len(matches)
            for m in matches:
                meta = m["metadata"]
                print_finding(
                    meta.get("severity", "MEDIUM"),
                    f'{m["cve_id"]} (Similarity: {m["similarity_score"]:.1%})',
                    m["description"][:100] + "...",
                )
        else:
            print(f"     No relevant CVEs found")

    # ---- Step 3: Build RAG-augmented prompt ----
    rag_context = kb.get_rag_context(software_stack, top_k=3)

    # Token optimization: shorter, focused system prompt
    system_prompt = """You are a threat intelligence analyst. Analyze the CVE data
retrieved from our knowledge base. For each relevant CVE:
1. Risk rating and exploitability assessment
2. Whether CVEs can be chained together
3. Prioritized remediation steps
4. Known threat actor groups (if any)
Use markdown. Be concise."""

    # The RAG context is injected here — this is the "Augmented" in RAG
    prompt = f"""Software stack: {json.dumps(software_stack)}

{rag_context}

Analyze the threat landscape for this stack based on the retrieved CVEs above.
Focus on what's most dangerous and actionable."""

    # ---- Step 4: Token-optimized LLM call ----
    input_tokens_estimate = len(prompt.split()) * 1.3  # rough estimate
    print(f"\n  📊 Estimated input tokens: ~{int(input_tokens_estimate)}")

    print("  🧠 Generating RAG-augmented threat briefing...")
    ai_analysis = call_llm(prompt, system_prompt)
    print_result(ai_analysis)

    return {
        "agent": "threat_intel_rag",
        "software_stack": software_stack,
        "rag_enabled": True,
        "total_cves_found": total_found,
        "cve_matches": {k: [{"cve_id": m["cve_id"], "score": m["similarity_score"]}
                            for m in v] for k, v in all_matches.items()},
        "knowledge_base_stats": stats,
        "ai_analysis": ai_analysis,
    }
