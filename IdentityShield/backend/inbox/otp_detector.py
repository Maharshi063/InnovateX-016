import re
from typing import Optional, Tuple

# Context triggers for OTP/verification codes
CONTEXT_PATTERNS = [
    r"verification\s*code",
    r"security\s*code",
    r"one[- ]?time\s*(?:password|passcode)",
    r"\botp\b",
    r"auth(?:entication)?\s*code",
    r"login\s*code",
    r"verify\s*your\s*(?:account|identity|email)",
    r"passcode",
    r"confirm(?:ation)?\s*code",
    r"access\s*code",
]

CONTEXT_REGEX = re.compile(r"|".join(CONTEXT_PATTERNS), re.IGNORECASE)

# Pattern looking for 4 to 8 digit numbers in proximity to trigger phrases
NUMERIC_CODE_REGEX = re.compile(r"\b([0-9]{4,8})\b")
STANDALONE_LINE_REGEX = re.compile(r"^\s*([0-9]{4,8})\s*$", re.MULTILINE)

# HTML Sanitization Patterns
DISALLOWED_TAGS_REGEX = re.compile(
    r"<\s*(script|style|iframe|object|embed|applet|meta|link|base|form|svg|canvas)[^>]*>.*?<\s*/\s*\1\s*>",
    re.IGNORECASE | re.DOTALL
)
SELF_CLOSING_DISALLOWED_REGEX = re.compile(
    r"<\s*(script|style|iframe|object|embed|applet|meta|link|base|form|svg|canvas)[^>]*/>",
    re.IGNORECASE
)
INLINE_HANDLERS_REGEX = re.compile(r"(\son\w+\s*=\s*['\"][^'\"]*['\"])", re.IGNORECASE)
JAVASCRIPT_URI_REGEX = re.compile(r"(href|src)\s*=\s*['\"]\s*javascript:[^'\"]*['\"]", re.IGNORECASE)

def detect_otp(subject: str, body_text: str) -> Tuple[bool, Optional[str]]:
    """
    Deterministically detects verification codes and OTPs.
    Avoids false-positive hits on dates, phone numbers, or street addresses.
    Returns: (otp_detected: bool, otp_code: Optional[str])
    """
    combined_content = f"{subject or ''}\n{body_text or ''}"

    # Check if context keywords exist
    has_context = bool(CONTEXT_REGEX.search(combined_content))
    if not has_context:
        return False, None

    # Priority 1: Check for a standalone number line (typical in verification emails)
    standalone_match = STANDALONE_LINE_REGEX.search(body_text or "")
    if standalone_match:
        code = standalone_match.group(1).strip()
        return True, code

    # Priority 2: Extract code immediately adjacent to a context trigger
    proximity_pattern = re.compile(
        r"(?:code|otp|passcode|is|:)\s*[:=-]?\s*([0-9]{4,8})\b",
        re.IGNORECASE
    )
    prox_match = proximity_pattern.search(combined_content)
    if prox_match:
        return True, prox_match.group(1).strip()

    # Priority 3: First numeric token with context present
    all_numbers = NUMERIC_CODE_REGEX.findall(combined_content)
    for num in all_numbers:
        # Exclude common four-digit years (e.g., 2020-2030) if other tokens exist
        if len(num) == 4 and num.startswith(("19", "20")):
            continue
        return True, num

    return False, None

def sanitize_html_payload(raw_html: str) -> str:
    """
    Neutralizes unsafe tags, scripts, tracking vectors, and inline event handlers
    before storage or rendering.
    """
    if not raw_html:
        return ""

    sanitized = DISALLOWED_TAGS_REGEX.sub("", raw_html)
    sanitized = SELF_CLOSING_DISALLOWED_REGEX.sub("", sanitized)
    sanitized = INLINE_HANDLERS_REGEX.sub("", sanitized)
    sanitized = JAVASCRIPT_URI_REGEX.sub(r'\1="#"', sanitized)

    return sanitized.strip()