from datetime import datetime, timezone
from urllib.parse import parse_qs
from typing import Tuple, Optional, Dict, Any

from .validators import validate_url_format
from .risk_engine import evaluate_url_heuristics

def analyze_url(raw_url: str) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
    """
    Main entry point for local heuristic URL security analysis.
    Performs validation, structural extraction, and heuristic security evaluation.
    Does NOT issue outbound network requests (SSRF-safe).
    Returns (success, error_message, structured_data).
    """
    is_valid, error_msg, components = validate_url_format(raw_url)
    if not is_valid or components is None:
        return False, error_msg, None

    score, risk_level, status_label, findings, indicators = evaluate_url_heuristics(components)

    query_count = len(parse_qs(components["query"]))

    result_data = {
        "url": components["url"],
        "domain": components["hostname"],
        "hostname": components["hostname"],
        "protocol": components["scheme"].upper(),
        "is_https": components["is_https"],
        "port": components["port"],
        "path": components["path"],
        "query_string": components["query"],
        "query_parameters": query_count,
        "risk_score": score,
        "risk_level": risk_level,
        "status": status_label,
        "findings": findings,
        "suspicious_indicators": indicators,
        "analysis_type": "Local Heuristic Inspection (No Outbound SSRF Probing)",
        "analyzed_at": datetime.now(timezone.utc).isoformat()
    }

    return True, None, result_data