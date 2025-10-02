# Honeypot Monitoring System Setup Instructions

## Files Overview
This project contains the following important files:
- `main.py` - Main entry point for the application
- `app.py` - Flask application with route definitions
- `honeypot.py` - Implementation of the honeypot services
- `logger.py` - Logging functionality
- `notifier.py` - Email notification system
- `/templates` - HTML templates for the web interface
- `/static` - JavaScript, CSS, and other static assets

## Download Instructions

### Method 1: Manual Download
1. In Replit, click on each file in the file explorer
2. Copy the content of each file
3. Save it to your local machine with the same name and directory structure

### Method 2: Exporting From Replit
1. Click on your profile picture in the top right
2. Go to "My Repls"
3. Find this project and click on the three dots (...) next to it
4. Select "Export to GitHub" if you have a GitHub account
   - Follow the prompts to create a new repository
   - Once on GitHub, you can clone or download as ZIP

## Running Locally

1. Make sure you have Python 3.11 installed
2. Install the required dependencies:
   ```
   pip install flask flask-sqlalchemy gunicorn email-validator psycopg2-binary
   ```
3. Run the application:
   ```
   python main.py
   ```
4. Open your browser and navigate to:
   ```
   http://localhost:5000
   ```

## Setting Up Honeypot Services

1. Navigate to the Configuration page
2. Select a service type (SSH, FTP, etc.)
3. Choose a port number (e.g., 2222 for SSH)
4. Click "Start Service"
5. The honeypot will begin listening for connection attempts

## Important Notes

- For educational purposes only
- Do not use on production systems without proper security measures
- Email notifications are simulated by default
- Always ensure you have permission to run security tools on your network