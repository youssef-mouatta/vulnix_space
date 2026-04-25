import os
import json
import time
from google import genai
from config import Config
from utils.logger import get_logger

logger = get_logger(__name__)

api_key = os.environ.get("GOOGLE_API_KEY", getattr(Config, "GOOGLE_API_KEY", ""))
client = None
if api_key:
    client = genai.Client(api_key=api_key)
else:
    logger.warning("GOOGLE_API_KEY not configured. AI functions will fail.")

# Primary model with ordered fallbacks for 503 overload situations
PRIMARY_MODEL = "gemini-2.5-flash"
FALLBACK_MODELS = [
    "gemini-2.0-flash",
    "gemini-1.5-flash",
]

def clean_output(text: str) -> str:
    text = text.strip()
    unwanted = ["Sure", "Here is", "Explanation", "Here are", "Certainly"]
    for phrase in unwanted:
        if text.lower().startswith(phrase.lower()):
            text = text[len(phrase):].lstrip(' :,-*\n')
    return text.strip()

def validate_output(text: str, issues_json_str: str, is_findings: bool = False) -> bool:
    if not isinstance(text, str) or not text.strip():
        return False
    forbidden = ["database", "credentials", "full system", "complete takeover", "server access"]
    text_lower = text.lower()
    issues_lower = issues_json_str.lower()
    
    for word in forbidden:
        if word in text_lower and word not in issues_lower:
            return False
            
    # For findings format, make sure Risk and Fix exist
    if is_findings:
        required = ("risk:", "impact:", "fix:", "priority:")
        if not all(label in text_lower for label in required):
            return False
            
    return True

def _call_model(model_name: str, prompt: str) -> str:
    """Single model call — raises on any error so safe_generate can handle it."""
    response = client.models.generate_content(model=model_name, contents=prompt)
    return clean_output(response.text)

def safe_generate(func, input_data, raw_data_str):
    """
    Resilient generation with model cascade + exponential backoff.
    On 503 overload errors the system falls through to cheaper/more available models
    before giving up and returning None.
    """
    is_findings = func.__name__ in {'generate_findings', 'generate_chat_findings'}
    models_to_try = [PRIMARY_MODEL] + FALLBACK_MODELS

    for model_name in models_to_try:
        for attempt in range(2):  # 2 attempts per model before cascading
            try:
                result = func(input_data, model_name=model_name)
                if validate_output(result, raw_data_str, is_findings):
                    return result
                # Output failed validation — no point retrying same model
                break
            except Exception as e:
                err_str = str(e)
                is_overloaded = "503" in err_str or "UNAVAILABLE" in err_str or "overloaded" in err_str.lower()
                logger.error(f"[{model_name}] attempt {attempt+1} failed: {e}")
                if is_overloaded:
                    wait = 2 ** attempt  # 1s, then 2s
                    logger.info(f"Model overloaded — waiting {wait}s before retry")
                    time.sleep(wait)
                else:
                    break  # Non-transient error, cascade to next model immediately
        else:
            continue  # Both attempts failed with overload — try next model

    logger.warning("All models exhausted — returning None")
    return None

def _format_input(issues):
    formatted = []
    for i in issues:
        formatted.append({
            "vulnerability_name": i.get("name"),
            "severity": i.get("severity"),
            "detected_reason": f"Detected because: {i.get('impact', 'Identified by scanner rules')}"
        })
    return json.dumps(formatted)


def _parse_issues(issues_json):
    try:
        issues = json.loads(issues_json) if isinstance(issues_json, str) else (issues_json or [])
        if isinstance(issues, list):
            return issues
    except (TypeError, ValueError, json.JSONDecodeError):
        pass
    return []


def _build_chat_evidence(issues):
    evidence = []
    for issue in issues:
        evidence.append(
            {
                "name": issue.get("name", "Unknown finding"),
                "severity": issue.get("severity", "Unknown"),
                "category": issue.get("category", "Uncategorized"),
                "impact": issue.get("impact", "No impact details"),
                "fix": issue.get("fix", "No remediation provided"),
                "classification": issue.get("classification", "Unknown"),
            }
        )
    return json.dumps(evidence)


def generate_chat_findings(prompt_payload: dict, model_name=PRIMARY_MODEL):
    prompt = (
        "Role: Senior Application Security Consultant.\n"
        "You are answering questions about one scan report using ONLY the provided evidence.\n"
        "Your response MUST follow this exact structure:\n"
        "RISK: <what is realistically dangerous>\n"
        "IMPACT: <what an attacker can achieve based on evidence>\n"
        "FIX: <clear implementation steps>\n"
        "PRIORITY: <Fix Now | Fix Soon | Monitor>\n\n"
        "Rules:\n"
        "- Evidence-only conclusions. If data is insufficient, state that explicitly.\n"
        "- Never claim catastrophic compromise without direct evidence.\n"
        "- No fear language, no speculation, no unsupported chain claims.\n"
        "- Keep concise and actionable.\n\n"
        f"Target: {prompt_payload.get('url', 'unknown')}\n"
        f"User question: {prompt_payload.get('question', '')}\n"
        "Report evidence:\n"
        f"{prompt_payload.get('evidence', '[]')}"
    )
    if not client:
        return "AI analysis unavailable"
    response = client.models.generate_content(model=model_name, contents=prompt)
    return clean_output(response.text)

def generate_summary(formatted_issues, model_name=PRIMARY_MODEL):
    prompt = (
        "Role: Senior Security Researcher.\n"
        "Write a direct, evidence-based executive summary (1-2 sentences) of the security status based ONLY on these issues.\n"
        "State the primary risk clearly. Do NOT use generic phrases like 'may exploit' or 'could be vulnerable'.\n"
        "Do NOT invent a 'full system takeover' or exaggerate impact without proof.\n"
        "FORBIDDEN PHRASES: 'may be exploited', 'could possibly', 'generic wording'.\n"
        "Issues:\n" + formatted_issues
    )
    if not client:
        return "AI analysis unavailable"
    response = client.models.generate_content(model=model_name, contents=prompt)
    return clean_output(response.text)

def generate_fix_priority(formatted_issues, model_name=PRIMARY_MODEL):
    prompt = (
        "Return top 3 issues to fix first from this data.\n"
        "Be clear, conservative, and short.\n"
        "Issues:\n" + formatted_issues
    )
    if not client:
        return "AI analysis unavailable"
    response = client.models.generate_content(model=model_name, contents=prompt)
    return clean_output(response.text)

def generate_chain(formatted_issues, model_name=PRIMARY_MODEL):
    prompt = (
        "Return real exploit chain only based on these issues.\n"
        "Format: A → B → C\n"
        "If none exist: return 'None'.\n"
        "Use conservative phrasing (e.g. 'enables'). DO NOT invent chains.\n\n"
        "Issues:\n" + formatted_issues
    )
    if not client:
        return "AI analysis unavailable"
    response = client.models.generate_content(model=model_name, contents=prompt)
    return clean_output(response.text)

def generate_findings(formatted_issues, model_name=PRIMARY_MODEL):
    prompt = (
        "Role: Senior Security Auditor.\n"
        "STRICT FORMAT FOR EACH VULNERABILITY:\n"
        "1. Risk: (Explain exactly what can happen based on the technical flaw. No vague text.)\n"
        "2. Impact: (Explain the real-world consequence: data theft, session hijack, etc.)\n"
        "3. Fix: (Give a clear, direct developer action.)\n\n"
        "FORBIDDEN PHRASES: 'may be exploited', 'possibly', 'could be'.\n\n"
        "RULES:\n"
        "* Only use provided data\n"
        "* Use strong, direct, factual language\n"
        "* If data is insufficient for a chain, state it clearly\n\n"
        "Data:\n" + formatted_issues
    )
    if not client:
        return "AI analysis unavailable"
    response = client.models.generate_content(model=model_name, contents=prompt)
    return clean_output(response.text)

def get_scan_summary(url: str, issues_json: str, meta: dict, user_tier: str = "free"):
    meta = meta or {}

    try:
        issues = json.loads(issues_json) if isinstance(issues_json, str) else issues_json
        real_finds = [i for i in issues if i.get("classification") in ("REAL_RISK", "SECURITY_WEAKNESS")]
    except (TypeError, ValueError, json.JSONDecodeError):
        real_finds = []

    if not real_finds:
        return {"response": "Secure Target Environment. No exploited paths or significant security weaknesses identified."}

    # PART 1: Control Input
    formatted_input = _format_input(real_finds)
    raw_str = json.dumps(real_finds)

    summary = safe_generate(generate_summary, formatted_input, raw_str) or "Attacker may exploit identified vulnerabilities."
    priority = safe_generate(generate_fix_priority, formatted_input, raw_str) or "Fix critical vulnerabilities."
    chain = safe_generate(generate_chain, formatted_input, raw_str) or "None"
    findings = safe_generate(generate_findings, formatted_input, raw_str) or "Risk analysis incomplete."

    combined = "\n\n".join(
        [
            f"Summary:\n{summary}",
            f"Top remediation focus:\n{priority}",
            f"Exploit chain perspective:\n{chain}",
            f"Structured findings:\n{findings}",
        ]
    )
    return {
        "response": combined.strip(),
        "summary": summary,
        "priority": priority,
        "chain": chain,
        "findings": findings,
    }

def chat_about_scan(url: str, issues_json: str, user_message: str, meta: dict = None, user_tier: str = "free"):
    issues = _parse_issues(issues_json)
    if not issues:
        return {"response": "I do not have enough verified findings in this scan to answer safely yet."}
    evidence = _build_chat_evidence(issues)
    raw_str = json.dumps(issues)
    payload = {"url": url, "question": user_message, "evidence": evidence}
    try:
        response_text = safe_generate(generate_chat_findings, payload, raw_str)
        if not response_text:
            return {"response": "I cannot verify a safe answer from the available scan evidence."}
        if not validate_output(response_text, raw_str):
            return {"response": "I cannot verify that claim based on the detected evidence."}
        for label in ("RISK:", "IMPACT:", "FIX:", "PRIORITY:"):
            if label not in response_text:
                return {"response": "I cannot produce a verified structured answer for this question yet."}
        return {"response": response_text}
    except Exception as exc:
        logger.error(f"AI Chat Error: {exc}")
        return {"error": str(exc)}

