# admin/notify.py
import os, smtplib
from email.message import EmailMessage

def send_mail(subject: str, body: str) -> bool:
    host = os.getenv("SMTP_HOST", "")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER", "")
    password = os.getenv("SMTP_PASS", "")
    mail_from = os.getenv("MAIL_FROM", "")
    mail_to = [x.strip() for x in os.getenv("MAIL_TO", "").split(",") if x.strip()]

    if not (host and mail_from and mail_to):
        print("[mail] skip: SMTP_HOST/MAIL_FROM/MAIL_TO が未設定")
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = mail_from
    msg["To"] = ", ".join(mail_to)
    msg.set_content(body)

    with smtplib.SMTP(host, port, timeout=30) as s:
        try:
            s.starttls()
        except Exception:
            pass
        if user and password:
            s.login(user, password)
        s.send_message(msg)
    return True
