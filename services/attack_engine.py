import requests
from urllib.parse import urlparse, urlencode, urlunparse

# ELITE PAYLOADS (Safe but detectable)
PAYLOADS = [
    {"val": "vulnix_ref", "level": "low"},
    {"val": "<h1>vulnix</h1>", "level": "medium"},
    {"val": "<script>console.log('vulnix')</script>", "level": "high"}
]

TIMEOUT = 4

def simulate_xss(url, session=None):
    """
    ELITE XSS SIMULATION: Detects reflection and classifies risk.
    Multi-step verification replaces naive string matching to avoid false positives.
    """
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    
    # 5. ADD TRUSTED DOMAIN FILTER
    trusted_domains = ["google.com", "facebook.com", "cloudflare.com"]
    if any(trusted in domain for trusted in trusted_domains):
        return {"level": "none"}

    caller = session if session else requests

    for p in PAYLOADS:
        # Check common parameters
        for param in ["q", "search", "id", "url", "redirect", "next", "callback"]:
            test_url = urlunparse(parsed._replace(query=urlencode({param: p["val"]})))
            try:
                r = caller.get(test_url, timeout=TIMEOUT)
                
                content_type = r.headers.get("Content-Type", "").lower()
                if "application/json" in content_type:
                    continue
                
                # 1. STRICT REFLECTION VALIDATION (Exact Match)
                # 3. ADD ENCODING DETECTION (If app encoded to &lt;, exact match fails)
                # 8. REMOVE NAIVE MATCHING
                if p["val"] not in r.text:
                    continue
                    
                # 2. ADD CONTEXT CHECK
                idx = r.text.find(p["val"])
                prefix = r.text[max(0, idx-250):idx].lower()
                
                # Reject reflection inside scripts from Google / CDN
                if "google-analytics.com" in prefix or "googletagmanager" in prefix or "cdn" in prefix:
                    continue
                    
                # 4. REQUIRE EXECUTION POSSIBILITY
                is_html_tag = "<" in p["val"] and ">" in p["val"]
                is_attribute = prefix.endswith('"') or prefix.endswith("'") or prefix.endswith('=')
                is_script_context = "<script" in prefix and prefix.rfind("<script") > prefix.rfind("</script")
                
                if not (is_html_tag or is_attribute or is_script_context):
                    continue  # Ignore: generic text reflection without execution context
                
                # 7. LOWER CONFIDENCE
                level = p["level"]
                if level == "high":
                    level = "medium"  # DO NOT mark HIGH to remain conservative
                elif not is_html_tag and not is_script_context:
                    level = "low"
                    
                return {
                    "level": level, 
                    "evidence": p["val"], 
                    "param": param
                }
            except:
                continue

    return {"level": "none"}

def check_open_redirect(url, session=None):
    """Probes for open redirect via common sink parameters."""
    parsed = urlparse(url)
    caller = session if session else requests
    
    test_params = ["redirect", "url", "next", "destination", "return", "jump", "go"]
    payload = "https://example.com" # Using example.com as a safe redirect target
    
    for param in test_params:
        test_url = urlunparse(parsed._replace(query=urlencode({param: payload})))
        try:
            r = caller.get(test_url, allow_redirects=False, timeout=TIMEOUT)
            location = r.headers.get("Location", "")
            if payload in location or location.startswith(payload):
                return {"found": True, "payload": payload, "param": param}
        except:
            pass
    return {"found": False}

def check_sensitive_files(base_url, session=None):
    """ELITE DISCOVERY: Probes for high-value infrastructure secrets."""
    paths = [
        "/.env", "/.git/config", "/docker-compose.yml", 
        "/.vscode/settings.json", "/backup.sql", "/config.json"
    ]
    caller = session if session else requests
    found = []

    for p in paths:
        try:
            url = base_url.rstrip("/") + p
            r = caller.get(url, timeout=TIMEOUT, allow_redirects=False)
            if r.status_code == 200 and len(r.text) > 10:
                content = r.text.lower()
                
                # Prevent false positives from SPAs / custom 404s returning HTML with 200 OK
                content_type = r.headers.get("Content-Type", "").lower()
                is_html_doc = "text/html" in content_type or "<html" in content or "<!doctype html" in content
                
                if not is_html_doc:
                    if any(k in content for k in ["db_", "password", "aws_", "secret", "[core]", "version"]):
                        found.append(p)
        except:
            pass
    return found