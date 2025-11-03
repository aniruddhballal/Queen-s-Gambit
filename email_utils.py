"""
Email utilities for sending OTP codes.
"""

import random
import smtplib
from email.mime.text import MIMEText


def send_otp_email(recipient_email, smtp_server, smtp_port, smtp_email, smtp_password):
    """
    Generate and send an OTP code via email.
    
    Args:
        recipient_email: str - Email address to send OTP to
        smtp_server: str - SMTP server address
        smtp_port: int - SMTP server port
        smtp_email: str - Email account to send from
        smtp_password: str - Password for the email account
        
    Returns:
        int - The generated OTP code, or None if sending failed
    """
    otp = random.randint(100000, 999999)
    subject = "Your OTP Code"
    body = f"Your OTP code is: {otp}"
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = smtp_email
    msg["To"] = recipient_email

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_email, smtp_password)
            server.sendmail(smtp_email, recipient_email, msg.as_string())
        return otp
    except Exception as e:
        print(f"Error sending email: {e}")
        return None