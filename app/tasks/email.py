import time
from app.core.celery_app import celery_app

@celery_app.task(name="send_test_email")
def send_test_email(email_to: str) -> str:
    """
    Simulate sending an email background task.
    """
    print(f"--- START: Sending email to {email_to} ---")
    
    # Simulate time-consuming work (e.g., SMTP connection)
    time.sleep(10) 
    
    print(f"--- END: Email sent to {email_to} ---")
    return f"Email successfully sent to {email_to}"