def generate_poc(issue, url):
    """
    Generates minimal and realistic Proof of Concept (PoC) payloads.
    """
    name = issue.get("name", "").lower()
    category = issue.get("category", "").lower()

    if "xss" in name or "injection" in category:
        return "<script>alert(1)</script>"

    if "open redirect" in name:
        return f"?redirect=https://evil.com"

    if "cookie" in category:
        return "document.cookie // Accessible via JS"

    if "exposure" in category:
        return f"/.env"

    if "transport" in category or "http" in name:
        return "http:// (unencrypted)"

    return None