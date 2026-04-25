import ipaddress
import re
import socket
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


def _ip_blocked(ip: ipaddress._BaseAddress) -> bool:
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
    )


def _hostname_resolves_to_safe_ips(hostname: str) -> bool:
    """
    Block hostnames that resolve to loopback, RFC1918, link-local, etc. (SSRF hardening).
    """
    if not hostname:
        return False
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False
    if not infos:
        return False
    seen_ip = False
    for _fam, _socktype, _proto, _canon, sockaddr in infos:
        if not sockaddr:
            continue
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        seen_ip = True
        if _ip_blocked(ip):
            return False
    return seen_ip


def is_valid_url(url):
    """
    Validation for user-supplied scan targets: scheme, host, literal IP rules,
    and DNS resolution must not point to non-public addresses.
    """
    try:
        parsed = urlparse(normalize_url(url))
        if parsed.scheme not in ("http", "https"):
            return False
        if not parsed.netloc:
            return False

        hostname = parsed.hostname
        if not hostname:
            return False

        if hostname.lower() == "localhost":
            return False

        try:
            ip = ipaddress.ip_address(hostname)
            if _ip_blocked(ip):
                return False
        except ValueError:
            if not _hostname_resolves_to_safe_ips(hostname):
                return False

        return True
    except Exception:
        return False


def sanitize_input(user_input):
    """Basic defense against XSS on server side."""
    if not isinstance(user_input, str):
        return user_input
    return re.sub(r"[<>]", "", user_input)
