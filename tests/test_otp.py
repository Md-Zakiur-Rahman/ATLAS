from auth.otp_manager import (
    otp_manager
)

email = input("Enter your test email: ")
if email:
    otp_manager.send_email_otp(email)
    print(f"OTP sent to {email}")
else:
    print("No email provided. Exiting.")