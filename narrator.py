"""
narrator.py  –  Gemini-powered narrative generator (REST API)
Uses raw HTTP requests to avoid dependencies on broken DLLs (cryptography).
"""

import os
import requests

def _get_api_key():
    """Get Gemini API key from environment or Streamlit secrets."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        try:
            import streamlit as st
            api_key = st.secrets["GEMINI_API_KEY"]
        except Exception:
            raise ValueError(
                "GEMINI_API_KEY not found. Set it as an environment variable or Streamlit secret."
            )
    return api_key.strip()


def generate_narrative(chain: dict) -> str:
    """Generate a 3-paragraph analyst report for an attack chain."""
    api_key = _get_api_key()

    events_block = "\n".join(
        f"  [{e['timestamp'].strftime('%H:%M:%S')}] "
        f"{e['event_type'].upper():<22} | "
        f"{e['tactic']:<28} | "
        f"{e['technique']:<40} | "
        f"score={e['anomaly_score']}"
        for e in chain["events"]
    )

    prompt = f"""You are a senior SOC analyst writing an executive-ready threat report.

=== INCIDENT DATA ===
Affected account : {chain['user']}
Attack origin IP : {chain['source_ip']}
Time window      : {chain['start_time'].strftime('%Y-%m-%d %H:%M')} to {chain['end_time'].strftime('%H:%M')} UTC
MITRE kill-chain : {' -> '.join(chain['tactics'])}
Risk score       : {chain['max_score']}/100
Priority         : {chain['priority']}

Event log:
{events_block}

=== INSTRUCTIONS ===
Write exactly three paragraphs separated by blank lines:

Paragraph 1 - WHAT HAPPENED: Narrate the attack step by step in plain English.
  Be specific about timestamps, techniques, and the attacker's likely goal.

Paragraph 2 - BUSINESS IMPACT: What data or systems are at risk right now?
  What is the worst-case outcome if this is not contained immediately?

Paragraph 3 - IMMEDIATE ACTIONS (numbered list 1. 2. 3.):
  Three concrete containment steps the on-call engineer should do in the next 15 minutes.

Rules: No bullet points except paragraph 3. No markdown headers. No fluff. Be direct."""

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}]
    }
    
    try:
        response = requests.post(url, json=payload, timeout=30)
        response.raise_for_status()
        result = response.json()
        return result['candidates'][0]['content']['parts'][0]['text']
    except Exception as e:
        import traceback
        print(f"DEBUG: Narrative failed. Response: {response.text if 'response' in locals() else 'No response'}")
        traceback.print_exc()
        return f"Error generating narrative: {str(e)}"


def generate_summary_headline(chain: dict) -> str:
    """One-sentence TL;DR for the alert card header."""
    api_key = _get_api_key()
    prompt = (
        f"Write a single sentence (max 20 words) summarising this security incident. "
        f"User: {chain['user']}, IP: {chain['source_ip']}, "
        f"kill-chain: {' -> '.join(chain['tactics'])}, "
        f"risk score: {chain['max_score']}/100. "
        f"No markdown. Start with the threat action."
    )
    
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent?key={api_key}"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}]
    }

    try:
        response = requests.post(url, json=payload, timeout=30)
        response.raise_for_status()
        result = response.json()
        return result['candidates'][0]['content']['parts'][0]['text'].strip()
    except Exception as e:
        print(f"DEBUG: Summary failed. Response: {response.text if 'response' in locals() else 'No response'}")
        return f"Summary unavailable: {str(e)}"
