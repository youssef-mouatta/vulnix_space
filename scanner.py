"""
Vulnix Scanner v5 — Production Exploit Detection Engine
Integrated with modular services for high-fidelity scanning.
"""

import requests
import socket
import threading
import time
import ipaddress
from urllib.parse import urlparse

# Modular Services
from services.attack_engine import simulate_xss, check_open_redirect, check_sensitive_files
from services.exploit_chains import detect_chains
from services.poc_generator import generate_poc
from services.priority_engine import prioritize

# ─────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────

TIMEOUT = 5
SESSION_KEYWORDS = ["session", "auth", "jwt", "sid", "login", "token"]
IGNORE_COOKIES = ["xsrf", "csrf", "_ga", "_gid"]

TRUSTED_PLATFORMS = [
    "google.com", "microsoft.com", "cloudflare.com",
    "github.com", "vercel.app", "netlify.app",
    "pages.dev", "firebaseapp.com", "aws.amazon.com", "azure.com"
]

USER_AGENT = "Mozilla/5.0 VulnixScanner/5.0 (Enterprise Exploit Detection)"

# Common ports to probe — covers web, SSH, FTP, mail, DB, cache
COMMON_PORTS = [
    (21, "FTP"),  (22, "SSH"),  (25, "SMTP"),
    (53, "DNS"),  (80, "HTTP"), (443, "HTTPS"),
    (3306, "MySQL"), (5432, "PostgreSQL"), (6379, "Redis"),
    (8080, "HTTP-Alt"), (8443, "HTTPS-Alt"), (27017, "MongoDB")
]

# ─────────────────────────────────────────────────────────────
# NETWORK RECON
# ─────────────────────────────────────────────────────────────

def probe_network_info(domain: str) -> dict:
    """
    Resolves the IP address of the target domain and checks
    which common service ports are open. Non-blocking; errors
    are silently ignored so scanning always continues.
    """
    info = {"ip": None, "open_ports": []}
    try:
        info["ip"] = socket.gethostbyname(domain)
    except socket.gaierror:
        return info

    for port, label in COMMON_PORTS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((info["ip"], port))
            sock.close()
            if result == 0:
                info["open_ports"].append({"port": port, "service": label})
        except OSError:
            pass

    return info

# ─────────────────────────────────────────────────────────────
# CACHE (Restored consistency with routes/scan.py)
# ─────────────────────────────────────────────────────────────

_cache = {}
_lock = threading.Lock()
CACHE_TTL = 300

def _get_cached(domain):
    with _lock:
        if domain in _cache:
            ts, data = _cache[domain]
            if time.monotonic() - ts < CACHE_TTL:
                return data
    return None

def _set_cache(domain, data):
    with _lock:
        _cache[domain] = (time.monotonic(), data)

# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────

def _issue(name, severity, category, impact, fix, confidence, classification, poc=None, owasp=None):
    return {
        "name": name,
        "severity": severity,
        "category": category,
        "impact": impact,
        "fix": fix,
        "confidence": confidence,
        "classification": classification,
        "poc": poc,
        "owasp": owasp
    }

def _is_trusted(domain):
    if not domain: return False
    return any(domain.endswith(d) for d in TRUSTED_PLATFORMS)


def _normalize_target(url: str):
    if not isinstance(url, str):
        return None, None
    candidate = url.strip()
    if not candidate:
        return None, None
    if not candidate.startswith(("http://", "https://")):
        candidate = "https://" + candidate
    parsed = urlparse(candidate)
    domain = parsed.hostname
    if not domain:
        return None, None
    return candidate, domain


def _is_private_or_loopback(hostname: str) -> bool:
    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return hostname in {"localhost"}

# ─────────────────────────────────────────────────────────────
# MAIN SCANNER
# ─────────────────────────────────────────────────────────────

def scan_website(url):
    url, domain = _normalize_target(url)
    if not url or not domain:
        return [_issue("Invalid Target URL", "HIGH", "Network",
                       "The provided target URL could not be parsed.",
                       "Use a valid public URL such as https://example.com.",
                       "High", "REAL_RISK")], "0", "High", False, {"ip": None, "open_ports": []}
    if _is_private_or_loopback(domain):
        return [_issue("Private Network Target Blocked", "HIGH", "Network",
                       "Private or local network targets are not allowed for SaaS security reasons.",
                       "Scan a public domain or run self-hosted scanning for internal assets.",
                       "High", "SECURITY_WEAKNESS")], "0", "High", False, {"ip": None, "open_ports": []}

    parsed = urlparse(url)

    cached = _get_cached(domain)
    if cached:
        # Handle old 4-tuple entries from cache stored before the network_info upgrade
        if len(cached) == 4:
            return cached + ({"ip": None, "open_ports": []},)
        return cached

    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT

    issues = []

    # Connection attempt
    try:
        r = session.get(url, timeout=TIMEOUT, allow_redirects=True)
        final_url = r.url
        is_https = final_url.startswith("https")
    except Exception as e:
        net_info = probe_network_info(domain) if domain else {"ip": None, "open_ports": []}
        return [_issue("Network Connection Failed", "HIGH", "Network",
                       f"Target is unreachable or blocked: {str(e)}",
                       "Verify URL visibility and firewall settings.",
                       "High", "REAL_RISK")], "0", "High", False, net_info

    headers = {k.lower(): v for k, v in r.headers.items()}
    trusted = _is_trusted(domain)

    # ─── ATTACK SIMULATION (Using Modular Services) ───

    xss_result = simulate_xss(url, session)
    http_vulnerable = False
    if not trusted:
        try:
            # Let requests follow all redirects naturally
            r_http = session.get(f"http://{domain}", timeout=5, allow_redirects=True)
            
            # SAFE CASE: If it eventually lands on https://, it enforces HTTPS.
            # VULNERABLE CASE: It strictly stays on http:// AND serves content (200 OK).
            if not r_http.url.startswith("https://"):
                if r_http.status_code == 200:
                    http_vulnerable = True
        except requests.RequestException:
            # If the request fails entirely, port 80 is likely closed/filtered (SAFE).
            pass

    exposed_files = check_sensitive_files(f"{parsed.scheme}://{domain}", session)
    redirect_result = check_open_redirect(url, session)

    missing_csp = "content-security-policy" not in headers
    missing_hsts = "strict-transport-security" not in headers
    missing_xframe = "x-frame-options" not in headers

    has_reflection = xss_result["level"] != "none"
    has_missing_httponly = False

    # ─── RULE 5: Sensitive File Exposure ───
    for f in exposed_files:
        issues.append(_issue(
            "Sensitive Data Source Exposed",
            "HIGH", "Exposure",
            "Server configuration files or backups are publicly accessible.",
            "Restrict access to sensitive files via server config.",
            "High", "REAL_RISK",
            owasp="A05"
        ))

    # ─── RULE 9: MITM Risk ───
    if http_vulnerable:
        issues.append(_issue(
            "Unencrypted Transport Protocol",
            "MEDIUM", "Transport",
            "Data transferred over HTTP is visible to anyone on the network.",
            "Force HTTPS redirection for all traffic.",
            "Medium", "SECURITY_WEAKNESS",
            owasp="A02"
        ))

    # ─── RULE 4: Open Redirect ───
    if redirect_result["found"]:
        issues.append(_issue(
            "Unvalidated URL Redirection",
            "MEDIUM", "Injection",
            "Attackers can redirect users to malicious phishing pages.",
            "Implement a whitelist for all redirect parameters.",
            "High", "REAL_RISK",
            owasp="A10"
        ))

    # ─── RULE 1: Reflected XSS ───
    if has_reflection and missing_csp:
        issues.append(_issue(
            "Client-Side Code Injection (XSS)",
            "HIGH", "Injection",
            "Malicious scripts can be executed in the user's browser.",
            "Encode all output and implement a strong CSP.",
            "High", "REAL_RISK",
            owasp="A03: Injection"
        ))

    # ─── COOKIE ANALYSIS (RULE 3) ───
    for c in session.cookies:
        name = c.name.lower()
        if any(x in name for x in IGNORE_COOKIES): continue
        is_session = any(x in name for x in SESSION_KEYWORDS)

        if is_session:
            secure_missing = not c.secure
            _rest = getattr(c, "_rest", None) or {}
            httponly_set = isinstance(_rest, dict) and "HttpOnly" in _rest
            if getattr(c, "has_nonstandard_attr", None):
                try:
                    httponly_set = httponly_set or c.has_nonstandard_attr("HttpOnly")
                except Exception:
                    pass
            httponly_missing = not httponly_set
            
            if httponly_missing:
                has_missing_httponly = True

            if secure_missing or httponly_missing:
                issues.append(_issue(
                    "Insecure Account Session",
                    "HIGH" if secure_missing else "MEDIUM",
                    "Cookie",
                    "Session tokens can be stolen via network sniffing or script access.",
                    "Enable Secure and HttpOnly flags on all auth cookies.",
                    "High", "SECURITY_WEAKNESS",
                    owasp="A02"
                ))

    # ─── HEADERS (RULES 6, 7, 8) ───
    if missing_xframe and not trusted:
        issues.append(_issue(
            "UI Redressing (Clickjacking)",
            "LOW", "Headers",
            "Users can be tricked into clicking hidden interface elements.",
            "Set X-Frame-Options to DENY or SAMEORIGIN.",
            "High", "SECURITY_WEAKNESS",
            owasp="A05"
        ))

    if missing_csp and not trusted and not has_reflection:
        issues.append(_issue(
            "Browser Protection Disabled (Missing CSP)",
            "MEDIUM", "Headers",
            "No Content Security Policy is enforced to prevent script injection.",
            "Define and deploy a Content-Security-Policy header.",
            "High", "SECURITY_WEAKNESS",
            owasp="A05"
        ))

    if missing_hsts and not trusted and is_https:
        issues.append(_issue(
            "HTTPS Enforcement Not Enabled (Missing HSTS)",
            "MEDIUM", "Headers",
            "Users might be downgraded to insecure HTTP connections.",
            "Add the Strict-Transport-Security header.",
            "High", "SECURITY_WEAKNESS",
            owasp="A05"
        ))

    # ─── CORRELATION ENGINE (RULE 2 & PART 3) ───
    
    if has_reflection and has_missing_httponly:
        issues.append(_issue(
            "Full Account Takeover Path",
            "HIGH", "Exploit Chain",
            "Combining XSS with unprotected cookies enables total session theft.",
            "Sanitize all inputs and lock cookies with HttpOnly.",
            "High", "REAL_RISK",
            owasp="A02: Broken Authentication"
        ))

    # ─── CORRELATION ENGINE: merge exploit chains into issues list ───
    # BUG FIX: detect_chains was called but its result was never added.
    correlated_chains = detect_chains(issues)
    for chain in correlated_chains:
        # Avoid duplicating if scanner.py's inline rule already added it
        if not any(i.get("name") == chain["name"] for i in issues):
            issues.append(chain)

    # ─── POC GENERATION (Link service) ───
    for i in issues:
        if not i.get("poc") and i.get("category") != "Exploit Chain":
            i["poc"] = generate_poc(i, url)

    # ─── SCORING ───
    chain_count = sum(1 for i in issues if i["category"] == "Exploit Chain")
    high_count = sum(1 for i in issues if i["severity"] == "HIGH" and i["category"] != "Exploit Chain")
    med_count = sum(1 for i in issues if i["severity"] == "MEDIUM")
    low_count = sum(1 for i in issues if i["severity"] == "LOW")

    deduction = (chain_count * 25) + (high_count * 15) + (med_count * 5) + (low_count * 2)
    score = int(max(0, min(100, 100 - deduction)))

    # Force caps for critical issues
    if chain_count > 0:
        score = min(score, 30)
    elif high_count > 0:
        score = min(score, 65)

    # ─── PRIORITY SORTING ───
    unique_issues = prioritize(issues)

    risk = "Low" if score >= 80 else "Medium" if score >= 50 else "High"
    network_info = probe_network_info(domain)

    result = (unique_issues, str(score), risk, False, network_info)
    _set_cache(domain, result)
    return result

def is_scan_failed(issues):
    return any(i.get("category") == "Network" for i in issues)

def has_real_issues(issues):
    return any(i["classification"] in ["REAL_RISK", "SECURITY_WEAKNESS"] for i in issues)