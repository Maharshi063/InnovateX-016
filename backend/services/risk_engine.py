def calculate_risk(
    unexpected_sender: bool = False,
    unknown_domain: bool = False,
    high_frequency: bool = False,
    suspicious_url: bool = False,
    known_exposure_indicator: bool = False,
    base_score: int = 0
) -> dict:
    """
    Transparent rule-based risk scoring engine.
    Scoring Model:
      - Unexpected sender:        +30
      - Unknown domain:           +20
      - High frequency spray:     +20
      - Suspicious link/URL:      +20
      - Known exposure indicator: +10
    Maximum: 100
    Severity:
      0–30   = Low
      31–60  = Medium
      61–80  = High
      81–100 = Critical
    """
    score = base_score
    reasons = []

    if unexpected_sender:
        score += 30
        reasons.append("Unexpected sender address targeting a single-merchant alias")
    if unknown_domain:
        score += 20
        reasons.append("Originating domain lacks matching organizational DKIM/SPF association")
    if high_frequency:
        score += 20
        reasons.append("Anomalous transmission volume surge detected within a short interval")
    if suspicious_url:
        score += 20
        reasons.append("Embedded redirection or heuristic credential probe detected in body")
    if known_exposure_indicator:
        score += 10
        reasons.append("Sender signature identified in shared marketing syndicate pools")

    score = min(max(score, 0), 100)

    if score <= 30:
        severity = "Low"
    elif score <= 60:
        severity = "Medium"
    elif score <= 80:
        severity = "High"
    else:
        severity = "Critical"

    return {
        "risk_score": score,
        "severity": severity,
        "reasons": reasons,
        "primary_reason": "; ".join(reasons) if reasons else "Routine verified transmission."
    }

def calculate_privacy_score(total_aliases: int, high_risk_count: int, unresolved_alerts: int, disabled_count: int) -> int:
    """
    Calculates overall system privacy score (0-100).
    Starts at 100.
    Penalties:
      - High risk/Critical exposure alert: -15 each
      - Medium/Unresolved alerts:          -5 each
    Mitigations:
      - Neutralizing via Disabling restores +3 each
    """
    if total_aliases == 0:
        return 100

    score = 100
    score -= (high_risk_count * 15)
    score -= (unresolved_alerts * 5)
    score += (disabled_count * 3)

    return min(max(score, 15), 100)