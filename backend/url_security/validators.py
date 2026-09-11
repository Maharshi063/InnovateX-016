import ipaddress
import re
from urllib.parse import urlparse
from typing import Tuple, Optional, Dict, Any

MAX_URL_LENGTH = 2048

def validate_url_format(raw_url: str) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
    """
    Validates that the provided URL is non-empty, within bounds, and strictly uses http/https.
    Rejects unsupported protocols (e.g., file://, javascript:, ftp:, data:).
    Returns (is_valid, error_message, parsed_components).
    """
    if not raw_url or not isinstance(raw_url, str):
        return False, "URL string is required.", None

    clean_url = raw_url.strip()
    if len(clean_url) == 0:
        return False, "URL string cannot be empty.", None

    if len(clean_url) > MAX_URL_LENGTH:
        return False, f"URL exceeds maximum allowed length of {MAX_URL_LENGTH} characters.", None

    # Enforce standard scheme prefix
    if not (clean_url.startswith("http://") or clean_url.startswith("https://")):
        return False, "Invalid protocol scheme. Only HTTP and HTTPS URLs are accepted.", None

    try:
        parsed = urlparse(clean_url)
    except Exception as exc:
        return False, f"Malformed URL syntax: {str(exc)}", None

    if not parsed.scheme or parsed.scheme.lower() not in ("http", "https"):
        return False, "Unsupported protocol scheme. Only http:// and https:// are permitted.", None

    if not parsed.netloc:
        return False, "URL is missing a valid destination hostname or netloc.", None

    hostname = parsed.hostname
    if not hostname:
        return False, "URL does not specify a valid domain or hostname.", None

    components = {
        "url": clean_url,
        "scheme": parsed.scheme.lower(),
        "is_https": parsed.scheme.lower() == "https",
        "netloc": parsed.netloc,
        "hostname": hostname,
        "port": parsed.port if parsed.port is not None else (443 if parsed.scheme.lower() == "https" else 80),
        "path": parsed.path or "/",
        "query": parsed.query or "",
        "fragment": parsed.fragment or ""
    }

    return True, None, components

def is_ip_address(hostname: str) -> bool:
    """Checks whether the hostname is a direct IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False