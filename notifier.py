import logging
import smtplib
import os
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def send_notification(recipient, subject, message):
    """Send an email notification about an attack.
    
    In a real-world scenario, this would send an actual email.
    For this project, we'll just log the notification.
    
    Args:
        recipient (str): Email address to send the notification to
        subject (str): Email subject
        message (str): Email message content
    """
    # Log the notification
    logger.info(f"NOTIFICATION: To: {recipient}, Subject: {subject}, Message: {message}")
    
    # In a real-world scenario, you would use SMTP to send the email
    # For this project, we'll just simulate it
    
    try:
        # Get email credentials from environment variables (if they exist)
        smtp_server = os.environ.get("SMTP_SERVER", "")
        smtp_port = int(os.environ.get("SMTP_PORT", "587"))
        smtp_username = os.environ.get("SMTP_USERNAME", "")
        smtp_password = os.environ.get("SMTP_PASSWORD", "")
        
        # If we don't have credentials, just log and return
        if not smtp_server or not smtp_username or not smtp_password:
            logger.info("Email not sent: SMTP credentials not configured")
            return
        
        # Create the email
        email = MIMEMultipart()
        email["From"] = smtp_username
        email["To"] = recipient
        email["Subject"] = subject
        
        # Add the message body
        email.attach(MIMEText(message, "plain"))
        
        # Connect to the SMTP server and send the email
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(email)
            
            logger.info(f"Email notification sent to {recipient}")
            
    except Exception as e:
        logger.error(f"Failed to send email notification: {e}")

def send_sms_notification(phone_number, message):
    """Send an SMS notification about an attack using Twilio.
    
    Args:
        phone_number (str): Phone number to send the SMS to (including country code)
        message (str): SMS message content
    """
    # Log the notification
    logger.info(f"SMS NOTIFICATION: To: {phone_number}, Message: {message}")
    
    try:
        # Get Twilio credentials from environment variables
        account_sid = os.environ.get("TWILIO_ACCOUNT_SID")
        auth_token = os.environ.get("TWILIO_AUTH_TOKEN")
        twilio_phone = os.environ.get("TWILIO_PHONE_NUMBER")
        
        # If we don't have Twilio credentials, just log and return
        if not account_sid or not auth_token or not twilio_phone:
            logger.info("SMS not sent: Twilio credentials not configured")
            return
        
        # Prepare the request to Twilio API
        url = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"
        data = {
            "From": twilio_phone,
            "To": phone_number,
            "Body": message
        }
        
        # Send the request
        response = requests.post(
            url,
            data=data,
            auth=(account_sid, auth_token)
        )
        
        # Check if the request was successful
        if response.status_code >= 200 and response.status_code < 300:
            logger.info(f"SMS notification sent to {phone_number}")
        else:
            logger.error(f"Failed to send SMS: {response.text}")
            
    except Exception as e:
        logger.error(f"Failed to send SMS notification: {e}")

def send_webhook_notification(webhook_url, data):
    """Send a webhook notification to an external system.
    
    Args:
        webhook_url (str): URL to send the webhook to
        data (dict): Data to include in the webhook
    """
    logger.info(f"WEBHOOK NOTIFICATION: To: {webhook_url}")
    
    try:
        headers = {'Content-Type': 'application/json'}
        response = requests.post(webhook_url, json=data, headers=headers, timeout=5)
        
        if response.status_code >= 200 and response.status_code < 300:
            logger.info(f"Webhook notification sent successfully to {webhook_url}")
        else:
            logger.error(f"Failed to send webhook: Status code {response.status_code}")
            
    except Exception as e:
        logger.error(f"Failed to send webhook notification: {e}")
