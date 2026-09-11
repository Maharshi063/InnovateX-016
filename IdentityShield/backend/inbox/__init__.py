"""
IdentityShield Inbound Email & OTP Processing Subsystem
"""

from .service import MailReceiver
from .otp_detector import detect_otp, sanitize_html_payload

__all__ = ["MailReceiver", "detect_otp", "sanitize_html_payload"]
