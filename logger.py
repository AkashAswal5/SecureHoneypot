import logging
import json
import os
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Set up a file handler if needed
log_file = "honeypot_attacks.log"
file_handler = logging.FileHandler(log_file)
file_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

def log_attack(log_entry):
    """Log an attack to the logger and to a file.
    
    Args:
        log_entry (dict): Dictionary containing attack details
    """
    source_ip = log_entry.get('source_ip', 'unknown')
    service = log_entry.get('service', 'unknown')
    attack_type = log_entry.get('attack_type', 'Unknown')
    
    # Log to the Python logger
    logger.info(f"Attack detected - IP: {source_ip}, Service: {service}, Type: {attack_type}")
    
    # Format the log entry for file logging
    timestamp = log_entry.get('timestamp', datetime.now().isoformat())
    port = log_entry.get('port', 0)
    data = log_entry.get('data', '')
    
    # Clean and truncate data if it's too long
    if len(data) > 1000:
        data = data[:1000] + "... (truncated)"
    
    # Create a formatted log line
    log_line = f"[{timestamp}] {source_ip}:{port} - {service} - {attack_type} - {data}\n"
    
    try:
        # Append to the log file
        with open(log_file, 'a') as f:
            f.write(log_line)
    except Exception as e:
        logger.error(f"Failed to write to log file: {e}")

def get_attack_logs():
    """Read attack logs from the log file.
    
    Returns:
        list: List of log entries
    """
    logs = []
    
    try:
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                for line in f:
                    try:
                        # Parse the log line
                        parts = line.strip().split(' - ', 3)
                        if len(parts) >= 4:
                            timestamp = parts[0].strip('[]')
                            ip_port = parts[1].split(':')
                            ip = ip_port[0]
                            port = int(ip_port[1]) if len(ip_port) > 1 else 0
                            service = parts[2]
                            attack_type, data = parts[3].split(' - ', 1) if ' - ' in parts[3] else (parts[3], '')
                            
                            logs.append({
                                'timestamp': timestamp,
                                'source_ip': ip,
                                'port': port,
                                'service': service,
                                'attack_type': attack_type,
                                'data': data
                            })
                    except Exception as e:
                        logger.error(f"Error parsing log line: {e}")
    except Exception as e:
        logger.error(f"Error reading log file: {e}")
    
    return logs
