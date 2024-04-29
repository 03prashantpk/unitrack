import smtplib
from email.mime.text import MIMEText

def send_emails(subject, body, sender_email, receiver_email, smtp_server, smtp_port, smtp_username=None, smtp_password=None):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = receiver_email

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()  # Start TLS encryption
        if smtp_username and smtp_password:
            server.login(smtp_username, smtp_password)
        server.send_message(msg)
        
        
# Example usage
sender_email = "support@enally.in"
smtp_server = "mail.enally.in" 
smtp_port = 587 
smtp_username = "support@enally.in"
smtp_password = "Nagaland@123pk"  
