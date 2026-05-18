"""
Stub for email_sender — Member B owns the real implementation.
This stub prevents ImportError until email_sender.py is complete.
"""

def send_otp_email(email: str, code: str) -> bool:
    print(f"[EMAIL STUB] OTP {code} would be sent to {email}")
    return True

def send_alert_email(email: str, subject: str, body: str) -> bool:
    print(f"[EMAIL STUB] Alert '{subject}' would be sent to {email}")
    return True