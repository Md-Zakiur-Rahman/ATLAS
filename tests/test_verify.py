from auth.otp_manager import (
    otp_manager
)

email = input(
    "Email: "
)
otp_manager.send_email_otp(
    email
)

otp = input(
    "Enter OTP: "
)

result = (
    otp_manager.verify_email_otp(
        email,
        otp
    )
)

print(
    "Verification Result:",
    result
)