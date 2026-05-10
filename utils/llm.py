"""
utils/llm.py - LLM Provider Abstraction Layer
Supports: OpenAI (GPT-4o-mini) and Anthropic (Claude Sonnet)
"""

import os
from dotenv import load_dotenv

load_dotenv()

PROVIDER = os.getenv("LLM_PROVIDER", "openai")
MODEL = os.getenv("LLM_MODEL", "gpt-4o-mini")


def call_llm(prompt: str, system_prompt: str = "") -> str:
    """
    Send a prompt to the configured LLM and return the response text.

    Args:
        prompt: The user message / main prompt
        system_prompt: Optional system-level instruction

    Returns:
        The LLM's response as a string
    """
    if PROVIDER == "openai":
        return _call_openai(prompt, system_prompt)
    elif PROVIDER == "anthropic":
        return _call_anthropic(prompt, system_prompt)
    else:
        raise ValueError(f"Unknown LLM_PROVIDER: {PROVIDER}. Use 'openai' or 'anthropic'.")


def _call_openai(prompt: str, system_prompt: str) -> str:
    from openai import OpenAI

    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    response = client.chat.completions.create(
        model=MODEL,
        messages=messages,
        temperature=0.3,
        max_tokens=4096,
    )
    return response.choices[0].message.content


def _call_anthropic(prompt: str, system_prompt: str) -> str:
    import anthropic

    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

    response = client.messages.create(
        model=MODEL,
        max_tokens=4096,
        system=system_prompt if system_prompt else "",
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text
