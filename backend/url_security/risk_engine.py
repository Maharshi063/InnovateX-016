from typing import List, Dict, Any, Tuple
from urllib.parse import parse_qs
from .validators import is_ip_address

# Specific keywords often associated with credential collection, account verification, or financial action
SUSPICIOUS_KEYWORDS = (
    "login", "verify", "verification", "secure", "account",
    "update", "password", "signin", "bank", "confirm", "wallet",
    "payment", "billing", "token", "claim", "free-gift", "security-check"
)

def evaluate_url_heuristics(components: Dict[str, Any]) -> Tuple[int, str, str, List[Dict[str, Any]], List[str]]:
    """
    Evaluates heuristic indicators based on URL structure without making outbound network requests.
    Returns: (risk_score, risk_level, status_label, findings, suspicious_indicators)
    """
    score = 0
    findings: List[Dict[str, Any]] = []
    indicators: List[str] = []

    is_https = components["is_https"]
    hostname = components["hostname"]
    port = components["port"]
    path = components["path"]
    query = components["query"]
    full_url = components["url"]

    # 1. Protocol / Transport Encryption Check
    if is_https:
        findings.append({
            "type": "HTTPS_ENCRYPTED",
            "severity": "LOW",
            "title": "HTTPS Transport Layer Detected",
            "description": "The URL negotiates TLS/SSL transport encryption. Note: Transport encryption safeguards transmission but does not verify website authenticity.",
            "badge": "LOW",
            "badgeStyle": "bg-emerald-50 text-emerald-700 border-emerald-200"
        })
    else:
        score += 35
        indicators.append("Unencrypted transmission transport (HTTP)")
        findings.append({
            "type": "HTTP_UNENCRYPTED",
            "severity": "HIGH",
            "title": "Unencrypted HTTP Transport",
            "description": "Communication travels in cleartext without TLS protection. Credentials, passwords, and tokens can be intercepted in transit.",
            "badge": "HIGH",
            "badgeStyle": "bg-rose-50 text-rose-700 border-rose-200"
        })

    # 2. IP Address in Hostname (common in direct probes or bypassed DNS)
    if is_ip_address(hostname):
        score += 30
        indicators.append("Hostname is a direct numerical IP address")
        findings.append({
            "type": "IP_HOSTNAME",
            "severity": "HIGH",
            "title": "Raw IP Address Specified",
            "description": "The target hostname directly references an IP address rather than a registered organizational domain name.",
            "badge": "HIGH",
            "badgeStyle": "bg-rose-50 text-rose-700 border-rose-200"
        })

    # 3. Punycode / IDN Homograph Indicator (xn--)
    if "xn--" in hostname.lower():
        score += 25
        indicators.append("Punycode / IDN encoding detected (potential lookalike)")
        findings.append({
            "type": "PUNYCODE_HOMOGRAPH",
            "severity": "MEDIUM",
            "title": "Punycode (IDN) Encoding Present",
            "description": "The domain utilizes Punycode ('xn--') representation. While legitimate for internationalized scripts, it is frequently leveraged for homograph lookalike domains.",
            "badge": "MEDIUM",
            "badgeStyle": "bg-amber-50 text-amber-800 border-amber-300"
        })

    # 4. Non-Standard Port Check (e.g., :8080, :8443, :2082)
    standard_port = 443 if is_https else 80
    if port != standard_port:
        score += 15
        indicators.append(f"Non-standard communication port: {port}")
        findings.append({
            "type": "UNUSUAL_PORT",
            "severity": "MEDIUM",
            "title": "Non-Standard Port Explicitly Declared",
            "description": f"URL connects via port {port} instead of conventional HTTP(S) ports ({standard_port}).",
            "badge": "MEDIUM",
            "badgeStyle": "bg-amber-50 text-amber-800 border-amber-300"
        })

    # 5. Excessive Subdomain Depth Check
    domain_labels = [label for label in hostname.split(".") if label]
    if len(domain_labels) >= 4 and not is_ip_address(hostname):
        score += 15
        indicators.append(f"Elevated subdomain hierarchy depth ({len(domain_labels)} labels)")
        findings.append({
            "type": "EXCESSIVE_SUBDOMAINS",
            "severity": "MEDIUM",
            "title": "Multi-Level Subdomain Structure",
            "description": "The hostname contains 4 or more label segments. Complex prefix hierarchies are sometimes used to imitate known brands on unrelated domains.",
            "badge": "MEDIUM",
            "badgeStyle": "bg-orange-50 text-orange-800 border-orange-300"
        })
    elif not is_ip_address(hostname):
        findings.append({
            "type": "NORMAL_DOMAIN_FORMAT",
            "severity": "INFO",
            "title": "Standard Domain Format",
            "description": "Domain naming format adheres to conventional top-level and second-level label conventions.",
            "badge": "LOW",
            "badgeStyle": "bg-emerald-50 text-emerald-700 border-emerald-200"
        })

    # 6. Sensitive Route & Query Keywords
    lower_full = full_url.lower()
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lower_full]
    if matched_keywords:
        score += 20
        indicators.append(f"Sensitive keywords in path/query ({', '.join(matched_keywords[:4])})")
        findings.append({
            "type": "SENSITIVE_KEYWORDS",
            "severity": "MEDIUM",
            "title": "Authentication / Financial Keywords Present",
            "description": f"The URL path or query contains sensitive tokens: {', '.join(matched_keywords[:5])}. Verify legitimacy before entering personal credentials.",
            "badge": "MEDIUM",
            "badgeStyle": "bg-amber-50 text-amber-800 border-amber-300"
        })
    else:
        findings.append({
            "type": "STANDARD_PATH",
            "severity": "INFO",
            "title": "Standard Path Structure",
            "description": "Resource path and query parameters show no overt phishing lure keyword patterns.",
            "badge": "INFO",
            "badgeStyle": "bg-slate-100 text-slate-700 border-slate-200"
        })

    # 7. Excessive Query Parameter Count
    parsed_queries = parse_qs(query)
    if len(parsed_queries) >= 5:
        score += 10
        indicators.append(f"High parameter density ({len(parsed_queries)} query keys)")
        findings.append({
            "type": "EXCESSIVE_PARAMS",
            "severity": "LOW",
            "title": "High Query Parameter Density",
            "description": f"URL carries {len(parsed_queries)} parameters, which may indicate extensive multi-stage tracking or redirect chains.",
            "badge": "LOW",
            "badgeStyle": "bg-slate-100 text-slate-700 border-slate-200"
        })

    # 8. Excessive URL Length
    if len(full_url) > 250:
        score += 10
        indicators.append(f"Extended URL length ({len(full_url)} chars)")

    # Normalize score range (0 - 100)
    score = min(max(score, 5 if is_https else 35), 100)

    # Classification
    if score <= 24:
        risk_level = "LOW"
        status_label = "LOW RISK"
    elif score <= 49:
        risk_level = "MEDIUM"
        status_label = "SUSPICIOUS"
    elif score <= 74:
        risk_level = "HIGH"
        status_label = "HIGH RISK"
    else:
        risk_level = "CRITICAL"
        status_label = "CRITICAL RISK"

    return score, risk_level, status_label, findings, indicators