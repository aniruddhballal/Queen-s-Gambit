import smtplib
import random
from email.mime.text import MIMEText
from config import Config

class EmailService:
    def __init__(self):
        self.smtp_server = Config.SMTP_SERVER
        self.smtp_port = Config.SMTP_PORT
        self.email = Config.SMTP_EMAIL
        self.password = Config.SMTP_PASSWORD
    
    def send_otp_email(self, recipient_email):
        otp = random.randint(10**(Config.OTP_LENGTH-1), 10**Config.OTP_LENGTH - 1)
        subject = "Your OTP Code"
        body = f"Your OTP code is: {otp}"
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = self.email
        msg["To"] = recipient_email

        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.email, self.password)
                server.sendmail(self.email, recipient_email, msg.as_string())
            return otp
        except Exception as e:
            print(f"Error sending email: {e}")
            return None