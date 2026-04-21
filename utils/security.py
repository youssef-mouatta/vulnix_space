import ipaddress
import re
from urllib.parse import urlparse


def normalize_url(url):
    """Allow users to submit bare domains while keeping validation strict."""
    if not isinstance(url, str):
        return url

    candidate = url.strip()
    if not candidate:
        return candidate

    parsed = urlparse(candidate)
    if parsed.scheme:
        return candidate

    return f"https://{candidate}"

def is_valid_url(url):
    """
    Basic validation preventing malicious internal requests (SSRF prevention schema).
    """
    try:
        parsed = urlparse(normalize_url(url))
        if parsed.scheme not in ['http', 'https']:
            return False
        if not parsed.netloc:
            return False

        hostname = parsed.hostname
        if not hostname:
            return False

        # SSRF Basic Defense (Block loopback, link-local, and private IPs)
        if hostname.lower() == "localhost":
            return False

        try:
            ip = ipaddress.ip_address(hostname)
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
            ):
                return False
        except ValueError:
            # Non-IP hostnames are allowed.
            pass

        return True
    except Exception:
        return False

def sanitize_input(user_input):
    """
    Basic defense against XSS on server side.
    """
    if not isinstance(user_input, str):
        return user_input
    # Remove script tags and potentially harmful characters
    return re.sub(r'[<>]', '', user_input)
