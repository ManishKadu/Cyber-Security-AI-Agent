"""
utils/token_optimizer.py - Token Optimization Utilities
========================================================
Techniques to reduce token usage and API costs.

Key insight: You pay for EVERY token — both input (your prompt)
and output (AI response). These utilities minimize both.
"""

import re
import json
from typing import Optional


def count_tokens_estimate(text: str) -> int:
    """
    Rough token count estimate (no tiktoken dependency needed).
    Rule of thumb: 1 token ≈ 4 characters or ≈ 0.75 words in English.

    For exact counts, use: pip install tiktoken
    """
    return max(1, int(len(text) / 4))


def summarize_logs_for_prompt(logs: str, findings: list[dict]) -> str:
    """
    OPTIMIZATION 1: Summarize logs before sending to LLM.

    Instead of sending ALL log lines (expensive), send only:
    - Lines that matched attack patterns (already found by regex)
    - Statistical summary of the rest
    - Total line count for context

    Token savings: 50-70% of log data tokens

    Args:
        logs: Raw log text
        findings: Rule-based scan results

    Returns:
        Compressed log summary (much fewer tokens)
    """
    lines = logs.strip().split("\n")
    total = len(lines)

    # Keep only suspicious lines
    suspicious_keywords = [
        "Failed", "ERROR", "CRITICAL", "WARNING",
        "denied", "attack", "injection", "backdoor",
        "BLOCK", "flooding", "BREAK-IN",
    ]
    suspicious_lines = []
    normal_count = 0

    for line in lines:
        if any(kw.lower() in line.lower() for kw in suspicious_keywords):
            suspicious_lines.append(line)
        else:
            normal_count += 1

    summary = f"""LOG SUMMARY ({total} total lines, {len(suspicious_lines)} suspicious, {normal_count} normal):

SUSPICIOUS LINES:
{chr(10).join(suspicious_lines)}

RULE-BASED FINDINGS: {json.dumps([f['rule'] for f in findings])}
"""
    return summary


def compress_system_prompt(verbose_prompt: str) -> str:
    """
    OPTIMIZATION 2: Compress system prompts.

    Remove unnecessary words while keeping instructions clear.
    LLMs understand terse instructions just as well as verbose ones.

    Token savings: 30-50% of system prompt tokens
    """
    # Remove filler phrases
    compressed = verbose_prompt
    fillers = [
        "Please note that", "It is important to", "Make sure to",
        "You should always", "Keep in mind that", "Be sure to",
        "In order to", "As an expert", "With your expertise",
    ]
    for filler in fillers:
        compressed = compressed.replace(filler, "")

    # Remove extra whitespace
    compressed = re.sub(r"\s+", " ", compressed).strip()
    return compressed


def should_skip_llm_call(findings: list[dict], threshold: int = 0) -> bool:
    """
    OPTIMIZATION 3: Skip LLM call when unnecessary.

    If rule-based scan found nothing suspicious, there's no need
    to spend tokens on AI analysis. Return early.

    Args:
        findings: Results from rule-based scan
        threshold: Minimum findings to trigger LLM call

    Returns:
        True if LLM call should be skipped
    """
    return len(findings) <= threshold


def truncate_output(max_tokens: int = 1024) -> int:
    """
    OPTIMIZATION 4: Limit max_tokens parameter.

    Default is often 4096, but most responses need only 500-1000.
    Lower max_tokens = lower cost (you pay for actual output tokens,
    but this prevents runaway responses).

    Returns:
        Optimized max_tokens value
    """
    return max_tokens


def estimate_cost(
    input_tokens: int,
    output_tokens: int,
    model: str = "gpt-4o-mini",
) -> dict:
    """
    Estimate the cost of an API call.

    Args:
        input_tokens: Number of prompt tokens
        output_tokens: Number of completion tokens
        model: Model name

    Returns:
        Cost breakdown dict
    """
    pricing = {
        "gpt-4o-mini": {"input": 0.15, "output": 0.60},      # per 1M tokens
        "gpt-4o": {"input": 2.50, "output": 10.00},
        "claude-sonnet": {"input": 3.00, "output": 15.00},
        "claude-haiku": {"input": 1.00, "output": 5.00},
    }

    rates = pricing.get(model, pricing["gpt-4o-mini"])
    input_cost = (input_tokens / 1_000_000) * rates["input"]
    output_cost = (output_tokens / 1_000_000) * rates["output"]

    return {
        "model": model,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "input_cost": round(input_cost, 6),
        "output_cost": round(output_cost, 6),
        "total_cost": round(input_cost + output_cost, 6),
    }


def build_optimized_prompt(
    data: str,
    findings: list[dict],
    system_prompt: str,
    compress: bool = True,
    summarize_data: bool = True,
) -> tuple[str, str, dict]:
    """
    MASTER OPTIMIZATION: Apply all techniques to build the cheapest
    effective prompt.

    Returns:
        (optimized_prompt, optimized_system_prompt, stats_dict)
    """
    stats = {
        "original_data_tokens": count_tokens_estimate(data),
        "original_system_tokens": count_tokens_estimate(system_prompt),
    }

    # Compress system prompt
    opt_system = compress_system_prompt(system_prompt) if compress else system_prompt
    stats["optimized_system_tokens"] = count_tokens_estimate(opt_system)

    # Summarize data
    if summarize_data and len(data) > 2000:
        opt_data = summarize_logs_for_prompt(data, findings)
    else:
        opt_data = data
    stats["optimized_data_tokens"] = count_tokens_estimate(opt_data)

    # Build final prompt
    opt_prompt = f"""Analyze this data:

{opt_data}

Findings so far: {json.dumps([f.get('rule', f.get('vulnerability', 'unknown')) for f in findings])}

Provide analysis with severity, attack type, and recommended actions. Be concise."""

    stats["final_input_tokens"] = count_tokens_estimate(opt_system + opt_prompt)
    stats["token_savings_pct"] = round(
        (1 - stats["final_input_tokens"] / max(1, stats["original_data_tokens"] + stats["original_system_tokens"])) * 100
    )

    return opt_prompt, opt_system, stats
