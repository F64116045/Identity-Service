import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from app.core.celery_app import celery_app
from app.core.config import settings

@celery_app.task(name="send_test_email")
def send_test_email(email_to: str) -> str:
    """
    Implements a real SMTP email sending task.
    """
    if not settings.SMTP_HOST:
        return "SMTP host is not configured. Skipping email."

    message = MIMEMultipart()
    message["From"] = f"{settings.EMAILS_FROM_NAME} <{settings.EMAILS_FROM_EMAIL}>"
    message["To"] = email_to
    message["Subject"] = "Identity Service Test Email"

    body = f"This is an automated test email from {settings.PROJECT_NAME}."
    message.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT)
        if settings.SMTP_TLS:
            server.starttls()
        
        server.login(settings.SMTP_USER or "", settings.SMTP_PASSWORD or "")
        server.send_message(message)
        server.quit()
        
        return f"Email successfully sent to {email_to}"
    except Exception as e:
        raise Exception(f"Failed to send email: {str(e)}")
    

@celery_app.task(name="send_verification_email")
def send_verification_email(email_to: str, token: str) -> str:
    """
    Send an HTML email with a verification link.
    """
    if not settings.SMTP_HOST:
        return "SMTP host not configured."

    # Important
    # For development, this link points to the backend API
    # In production, this should point to Frontend
    verify_url = f"http://localhost:8000{settings.API_V1_STR}/auth/verify-email?token={token}"

    message = MIMEMultipart()
    message["From"] = f"{settings.EMAILS_FROM_NAME} <{settings.EMAILS_FROM_EMAIL}>"
    message["To"] = email_to
    message["Subject"] = "Verify Your Account"

    html_content = f"""
    <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6;">
            <div style="max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
                <h2 style="color: #333;">Welcome to {settings.PROJECT_NAME}!</h2>
                <p>Thank you for registering. Please click the button below to verify your email and activate your account:</p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{verify_url}" 
                       style="background-color: #4CAF50; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold;">
                       Verify Email Address
                    </a>
                </div>
                <p>If the button above doesn't work, copy and paste this link into your browser:</p>
                <p style="word-break: break-all; color: #666;">{verify_url}</p>
                <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;">
                <p style="font-size: 0.8em; color: #999;">This link will expire in 24 hours.</p>
            </div>
        </body>
    </html>
    """
    message.attach(MIMEText(html_content, "html"))

    try:
        server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT)
        if settings.SMTP_TLS:
            server.starttls()
        server.login(settings.SMTP_USER or "", settings.SMTP_PASSWORD or "")
        server.send_message(message)
        server.quit()
        return f"Verification email sent to {email_to}"
    except Exception as e:
        raise Exception(f"SMTP error: {str(e)}")