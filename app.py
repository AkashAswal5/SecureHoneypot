import os
import logging
import csv
import io
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, Response, send_file
from datetime import datetime, timedelta
import json
import threading
import time

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "honeypot_default_secret")

# In-memory storage for logs
attack_logs = []
active_services = {}
notification_settings = {
    'email_enabled': False,
    'email_address': '',
    'frequency': 'immediate',  # immediate, hourly, daily
    'threshold': 5,  # Number of attacks before notification
    'sms_enabled': False,
    'phone_number': '',
    'webhook_enabled': False,
    'webhook_url': ''
}

# Import modules after app is initialized
from honeypot import HoneypotService
from logger import log_attack, get_attack_logs
from notifier import send_notification, send_sms_notification, send_webhook_notification
from geoip_handler import get_ip_location, get_ip_threat_intel, download_geolite_db

@app.route('/')
def index():
    """Render the main dashboard page."""
    return render_template('dashboard.html', 
                          logs_count=len(attack_logs), 
                          active_services=active_services)

@app.route('/logs')
def logs():
    """Display the logs page with attack logs."""
    return render_template('logs.html', logs=attack_logs)

@app.route('/api/logs')
def api_logs():
    """Return attack logs as JSON for AJAX requests."""
    return jsonify(attack_logs)

@app.route('/api/stats')
def api_stats():
    """Return statistics about attacks."""
    if not attack_logs:
        return jsonify({
            'total_attacks': 0,
            'unique_ips': 0,
            'services': {},
            'recent_attacks': []
        })
    
    unique_ips = set(log['source_ip'] for log in attack_logs)
    services = {}
    for log in attack_logs:
        service = log['service']
        services[service] = services.get(service, 0) + 1
    
    # Get the 10 most recent attacks
    recent_attacks = sorted(attack_logs, key=lambda x: x['timestamp'], reverse=True)[:10]
    
    return jsonify({
        'total_attacks': len(attack_logs),
        'unique_ips': len(unique_ips),
        'services': services,
        'recent_attacks': recent_attacks
    })

@app.route('/configuration', methods=['GET', 'POST'])
def configuration():
    """Handle the configuration page and form submissions."""
    global notification_settings
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'save_notification':
            # Email settings
            notification_settings['email_enabled'] = 'email_enabled' in request.form
            notification_settings['email_address'] = request.form.get('email_address', '')
            
            # SMS settings
            notification_settings['sms_enabled'] = 'sms_enabled' in request.form
            notification_settings['phone_number'] = request.form.get('phone_number', '')
            
            # Webhook settings
            notification_settings['webhook_enabled'] = 'webhook_enabled' in request.form
            notification_settings['webhook_url'] = request.form.get('webhook_url', '')
            
            # General notification settings
            notification_settings['frequency'] = request.form.get('frequency', 'immediate')
            notification_settings['threshold'] = int(request.form.get('threshold', 5))
            
            # Check if we need to request API keys for the configured services
            api_keys_needed = []
            messages = []
            
            if notification_settings['sms_enabled'] and not all([
                os.environ.get("TWILIO_ACCOUNT_SID"),
                os.environ.get("TWILIO_AUTH_TOKEN"),
                os.environ.get("TWILIO_PHONE_NUMBER")
            ]):
                messages.append("SMS notifications enabled but Twilio credentials are missing.")
                api_keys_needed.extend(["TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_PHONE_NUMBER"])
            
            if api_keys_needed:
                # Log which API keys are needed
                logger.warning(f"Missing API keys: {', '.join(api_keys_needed)}")
                for message in messages:
                    flash(message + " Notifications will be simulated.", 'warning')
            
            flash('Notification settings updated successfully', 'success')
        
        elif action == 'start_service':
            service_type = request.form.get('service_type')
            port = int(request.form.get('port', 0))
            
            if port < 1 or port > 65535:
                flash('Invalid port number', 'danger')
            elif port in [p for s, p, _ in active_services.values()]:
                flash(f'Port {port} is already in use', 'danger')
            else:
                service_id = len(active_services) + 1
                try:
                    honeypot = HoneypotService(service_type, port, service_id)
                    honeypot_thread = threading.Thread(target=honeypot.start)
                    honeypot_thread.daemon = True
                    honeypot_thread.start()
                    
                    active_services[service_id] = (service_type, port, honeypot)
                    flash(f'{service_type} honeypot started on port {port}', 'success')
                except Exception as e:
                    flash(f'Failed to start honeypot: {str(e)}', 'danger')
                    logger.error(f"Error starting honeypot: {e}")
        
        elif action == 'stop_service':
            service_id = int(request.form.get('service_id', 0))
            if service_id in active_services:
                service_type, port, honeypot = active_services[service_id]
                honeypot.stop()
                del active_services[service_id]
                flash(f'{service_type} honeypot on port {port} stopped', 'success')
        
        return redirect(url_for('configuration'))
    
    return render_template('configuration.html', 
                           active_services=active_services,
                           notification_settings=notification_settings)

@app.route('/clear_logs', methods=['POST'])
def clear_logs():
    """Clear all attack logs."""
    global attack_logs
    attack_logs = []
    flash('All logs have been cleared', 'success')
    return redirect(url_for('logs'))

# Helper function to add a log entry is now replaced by the enhanced version below

# Enhanced logging function with geolocation and threat intel
def add_log_entry(service, source_ip, port, data, attack_type="Unknown"):
    """Add a log entry with enhanced information to the attack_logs global variable."""
    timestamp = datetime.now().isoformat()
    
    # Basic log entry
    log_entry = {
        'id': len(attack_logs) + 1,
        'timestamp': timestamp,
        'service': service,
        'source_ip': source_ip,
        'port': port,
        'data': data,
        'attack_type': attack_type
    }
    
    # Add geolocation data if possible
    try:
        geo_data = get_ip_location(source_ip)
        log_entry['geo'] = geo_data
    except Exception as e:
        logger.error(f"Error getting geolocation data: {e}")
        log_entry['geo'] = {
            'country': 'Unknown',
            'country_code': 'XX',
            'city': 'Unknown',
            'latitude': 0,
            'longitude': 0
        }
    
    # Add threat intelligence data if possible
    try:
        threat_data = get_ip_threat_intel(source_ip)
        log_entry['threat_intel'] = threat_data
    except Exception as e:
        logger.error(f"Error getting threat intelligence data: {e}")
        log_entry['threat_intel'] = {
            'risk_score': 0,
            'is_known_attacker': False,
            'threat_type': 'Unknown',
        }
    
    # Add to logs and handle notifications
    attack_logs.append(log_entry)
    log_attack(log_entry)
    
    # Check if we need to send email notification
    if notification_settings['email_enabled']:
        if notification_settings['frequency'] == 'immediate':
            send_notification(
                notification_settings['email_address'],
                "Honeypot Alert", 
                f"Attack detected from {source_ip} ({log_entry['geo']['country']}) on {service} service. Type: {attack_type}"
            )
        elif len(attack_logs) % notification_settings['threshold'] == 0:
            send_notification(
                notification_settings['email_address'],
                "Honeypot Alert - Threshold Reached",
                f"Threshold of {notification_settings['threshold']} attacks has been reached"
            )
    
    # Check if we need to send SMS notification
    if notification_settings.get('sms_enabled') and notification_settings.get('phone_number'):
        send_sms_notification(
            notification_settings['phone_number'],
            f"Honeypot Alert: Attack from {source_ip} ({log_entry['geo']['country']}) on {service}. Type: {attack_type}"
        )
    
    # Check if we need to send webhook notification
    if notification_settings.get('webhook_enabled') and notification_settings.get('webhook_url'):
        send_webhook_notification(
            notification_settings['webhook_url'],
            log_entry
        )

@app.route('/export/csv')
def export_csv():
    """Export attack logs as CSV file."""
    if not attack_logs:
        flash('No logs to export', 'warning')
        return redirect(url_for('logs'))
    
    # Create CSV file in memory
    output = io.StringIO()
    csv_writer = csv.writer(output)
    
    # Write CSV header
    csv_writer.writerow(['ID', 'Timestamp', 'Service', 'Source IP', 'Port', 'Attack Type', 
                         'Country', 'City', 'Latitude', 'Longitude', 'Risk Score', 'Data'])
    
    # Write data rows
    for log in attack_logs:
        geo = log.get('geo', {})
        threat = log.get('threat_intel', {})
        
        csv_writer.writerow([
            log.get('id', ''),
            log.get('timestamp', ''),
            log.get('service', ''),
            log.get('source_ip', ''),
            log.get('port', ''),
            log.get('attack_type', ''),
            geo.get('country', 'Unknown'),
            geo.get('city', 'Unknown'),
            geo.get('latitude', 0),
            geo.get('longitude', 0),
            threat.get('risk_score', 0),
            log.get('data', '')[:100]  # Truncate data to reasonable length
        ])
    
    # Prepare response
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=honeypot_logs.csv"}
    )

@app.route('/export/json')
def export_json():
    """Export attack logs as JSON file."""
    if not attack_logs:
        flash('No logs to export', 'warning')
        return redirect(url_for('logs'))
    
    # Create JSON file
    json_data = json.dumps(attack_logs, indent=2)
    
    # Create in-memory file-like object
    mem = io.BytesIO()
    mem.write(json_data.encode('utf-8'))
    mem.seek(0)
    
    return send_file(
        mem,
        mimetype='application/json',
        as_attachment=True,
        download_name='honeypot_logs.json'
    )

@app.route('/api/advanced_stats')
def api_advanced_stats():
    """Return advanced statistics about attacks."""
    if not attack_logs:
        return jsonify({
            'attack_types': {},
            'country_distribution': {},
            'hourly_distribution': [0] * 24,
            'top_attackers': [],
            'risk_score_distribution': {
                'low': 0,
                'medium': 0,
                'high': 0,
                'critical': 0
            }
        })
    
    # Attack types distribution
    attack_types = {}
    for log in attack_logs:
        attack_type = log.get('attack_type', 'Unknown')
        attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
    
    # Country distribution
    country_distribution = {}
    for log in attack_logs:
        geo = log.get('geo', {})
        country = geo.get('country', 'Unknown')
        country_distribution[country] = country_distribution.get(country, 0) + 1
    
    # Hourly distribution
    hourly_distribution = [0] * 24
    for log in attack_logs:
        try:
            timestamp = log.get('timestamp', '')
            dt = datetime.fromisoformat(timestamp)
            hour = dt.hour
            hourly_distribution[hour] += 1
        except (ValueError, IndexError):
            pass
    
    # Top attackers
    ip_attack_count = {}
    for log in attack_logs:
        ip = log.get('source_ip', '')
        ip_attack_count[ip] = ip_attack_count.get(ip, 0) + 1
    
    top_attackers = [{"ip": ip, "count": count, "country": next((log.get('geo', {}).get('country', 'Unknown') 
                     for log in attack_logs if log.get('source_ip') == ip), 'Unknown')}
                    for ip, count in sorted(ip_attack_count.items(), key=lambda x: x[1], reverse=True)[:10]]
    
    # Risk score distribution
    risk_levels = {
        'low': 0,
        'medium': 0,
        'high': 0,
        'critical': 0
    }
    
    for log in attack_logs:
        threat = log.get('threat_intel', {})
        risk_score = threat.get('risk_score', 0)
        
        if risk_score < 25:
            risk_levels['low'] += 1
        elif risk_score < 50:
            risk_levels['medium'] += 1
        elif risk_score < 75:
            risk_levels['high'] += 1
        else:
            risk_levels['critical'] += 1
    
    return jsonify({
        'attack_types': attack_types,
        'country_distribution': country_distribution,
        'hourly_distribution': hourly_distribution,
        'top_attackers': top_attackers,
        'risk_score_distribution': risk_levels
    })

@app.route('/api/threat_map')
def api_threat_map():
    """Return geolocation data for mapping attacks."""
    if not attack_logs:
        return jsonify([])
    
    map_data = []
    for log in attack_logs:
        geo = log.get('geo', {})
        if geo.get('latitude') and geo.get('longitude'):
            map_data.append({
                'latitude': geo.get('latitude', 0),
                'longitude': geo.get('longitude', 0),
                'ip': log.get('source_ip', ''),
                'attack_type': log.get('attack_type', 'Unknown'),
                'country': geo.get('country', 'Unknown'),
                'timestamp': log.get('timestamp', ''),
                'service': log.get('service', '')
            })
    
    return jsonify(map_data)

@app.route('/advanced')
def advanced_dashboard():
    """Render the advanced analytics dashboard page."""
    # Check if we have the GeoLite2 database
    have_geolite = download_geolite_db()
    
    return render_template('advanced.html', 
                          logs_count=len(attack_logs), 
                          active_services=active_services,
                          have_geolite=have_geolite)

@app.route('/ml')
def ml_dashboard():
    """Render the machine learning analytics dashboard page."""
    attack_logs = get_attack_logs()
    logs_count = len(attack_logs)
    
    # Check if we have enough data for ML
    ml_ready = logs_count >= 10
    
    return render_template('ml_dashboard.html',
                          logs_count=logs_count,
                          active_services=active_services,
                          ml_ready=ml_ready)

# HTTP Honeypot API endpoints
@app.route('/api/honeypot/http/login', methods=['POST'])
def http_honeypot_login():
    """Handle login attempts from the HTTP honeypot admin panel."""
    data = request.json
    
    try:
        username = data.get('username', '')
        password = data.get('password', '')
        timestamp = data.get('timestamp', datetime.now().isoformat())
        
        # Get client IP address
        source_ip = request.remote_addr
        
        # Log the attempted login
        attack_data = f"Login attempt with username: {username}, password: {password}"
        add_log_entry('HTTP-AdminPanel', source_ip, 80, attack_data, attack_type="Credential Stuffing")
        
        return jsonify({'status': 'success', 'message': 'Attack logged'})
    except Exception as e:
        logger.error(f"Error processing HTTP honeypot login: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/honeypot/http/mysql_login', methods=['POST'])
def http_honeypot_mysql_login():
    """Handle login attempts from the HTTP honeypot phpMyAdmin panel."""
    data = request.json
    
    try:
        username = data.get('username', '')
        password = data.get('password', '')
        server = data.get('server', '')
        database = data.get('database', '')
        timestamp = data.get('timestamp', datetime.now().isoformat())
        
        # Get client IP address
        source_ip = request.remote_addr
        
        # Log the attempted login
        attack_data = f"MySQL login attempt - Server: {server}, Username: {username}, Password: {password}, Database: {database}"
        add_log_entry('HTTP-phpMyAdmin', source_ip, 80, attack_data, attack_type="Database Access Attempt")
        
        return jsonify({'status': 'success', 'message': 'Attack logged'})
    except Exception as e:
        logger.error(f"Error processing HTTP honeypot MySQL login: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

# Serve HTTP honeypot files
@app.route('/honeypot/http/<path:filename>')
def serve_http_honeypot(filename):
    """Serve static files for the HTTP honeypot while logging access attempts."""
    # Log the access attempt
    source_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    query_string = request.query_string.decode('utf-8', errors='ignore')
    
    attack_data = f"HTTP resource access - Path: /{filename}, Query: {query_string}, User-Agent: {user_agent}"
    attack_type = "Reconnaissance"
    
    # Determine more specific attack types based on requested resources and query parameters
    if 'admin' in filename:
        attack_type = "Admin Panel Access Attempt"
    elif 'setup' in filename:
        attack_type = "Configuration Info Gathering"
    elif 'phpmyadmin' in filename:
        attack_type = "Database Management Access Attempt"
    elif 'backup' in filename:
        attack_type = "Sensitive Data Access Attempt"
    elif 'uploads' in filename:
        attack_type = "File System Access Attempt"
    elif 'login.php' in filename:
        attack_type = "Authentication Attack"
        # Check for potential XSS in error parameter
        if 'error=' in query_string and ('<script>' in query_string or 'alert(' in query_string):
            attack_type = "Cross-Site Scripting (XSS)"
    elif 'search.php' in filename:
        attack_type = "Information Gathering"
        # Check for SQL injection in search query
        if 'q=' in query_string and any(x in query_string for x in ["'", "--", "/*", "union", "1=1", "="]):
            attack_type = "SQL Injection"
    elif 'user.php' in filename:
        attack_type = "User Information Access"
        # Check for SQL injection in user ID
        if 'id=' in query_string and any(x in query_string for x in ["'", "--", "/*", "union", "1=1", "="]):
            attack_type = "SQL Injection"
    
    add_log_entry('HTTP-Static', source_ip, 80, attack_data, attack_type=attack_type)
    
    # Serve the requested file from the static directory
    return app.send_static_file(f'honeypots/http/{filename}')

@app.route('/honeypot')
def honeypot_landing():
    """Serve the honeypot landing page."""
    source_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    
    attack_data = f"HTTP honeypot landing page access - User-Agent: {user_agent}"
    add_log_entry('HTTP-Landing', source_ip, 80, attack_data, attack_type="Initial Reconnaissance")
    
    return app.send_static_file('honeypots/http/landing.html')

# Machine Learning Routes
@app.route('/api/ml/anomalies', methods=['GET'])
def api_ml_anomalies():
    """Return anomalies detected by ML model."""
    try:
        from ml_analyzer import HoneypotMLAnalyzer
        
        attack_logs = get_attack_logs()
        
        if not attack_logs:
            return jsonify({'error': 'No attack logs found'})
        
        # Create and train the ML analyzer
        analyzer = HoneypotMLAnalyzer()
        
        # Detect anomalies
        anomaly_indices = analyzer.detect_anomalies(attack_logs)
        
        # If no model exists yet, train it first
        if not anomaly_indices and len(attack_logs) > 10:
            analyzer.train_anomaly_detector(attack_logs)
            anomaly_indices = analyzer.detect_anomalies(attack_logs)
        
        # Extract anomalies from logs
        anomalies = [attack_logs[i] for i in anomaly_indices]
        
        # Add explanation to each anomaly
        for anomaly in anomalies:
            anomaly['anomaly_explanation'] = "This attack pattern shows unusual characteristics detected by machine learning model."
        
        return jsonify({
            'anomalies_found': len(anomalies),
            'anomalies': anomalies,
            'total_logs_analyzed': len(attack_logs)
        })
    
    except Exception as e:
        return jsonify({'error': f'Error analyzing anomalies: {str(e)}'})

@app.route('/api/ml/predict_trends', methods=['GET'])
def api_ml_predict_trends():
    """Predict attack trends for the next 24 hours."""
    try:
        from ml_analyzer import HoneypotMLAnalyzer
        
        attack_logs = get_attack_logs()
        
        if not attack_logs:
            return jsonify({'error': 'No attack logs found'})
        
        # Check if we have enough data
        if len(attack_logs) < 24:
            return jsonify({'error': 'Not enough data for prediction (need at least 24 hours of logs)'})
        
        # Get service parameter if provided
        service = request.args.get('service', None)
        hours = int(request.args.get('hours', 24))
        
        # Create ML analyzer
        analyzer = HoneypotMLAnalyzer()
        
        # Train time series model if needed
        model_filename = f"time_series_model{'_' + service if service else ''}.h5"
        model_path = os.path.join('models', model_filename)
        
        if not os.path.exists(model_path):
            trained = analyzer.train_time_series_model(attack_logs, target_service=service)
            if not trained:
                return jsonify({'error': 'Failed to train prediction model'})
        
        # Make predictions
        predictions = analyzer.predict_attack_trends(hours_ahead=hours, target_service=service)
        
        if not predictions:
            return jsonify({'error': 'Failed to generate predictions'})
        
        # Format the predictions with timestamps
        now = datetime.now()
        prediction_data = []
        
        for i, count in enumerate(predictions):
            future_time = now + timedelta(hours=i+1)
            prediction_data.append({
                'timestamp': future_time.strftime('%Y-%m-%d %H:%M:%S'),
                'predicted_attacks': max(0, round(float(count)))
            })
        
        return jsonify({
            'service': service if service else 'all',
            'hours_predicted': hours,
            'predictions': prediction_data
        })
    
    except Exception as e:
        return jsonify({'error': f'Error predicting attack trends: {str(e)}'})

@app.route('/api/ml/attack_report', methods=['GET'])
def api_ml_attack_report():
    """Generate a comprehensive attack pattern report."""
    try:
        from ml_analyzer import HoneypotMLAnalyzer
        
        attack_logs = get_attack_logs()
        
        if not attack_logs:
            return jsonify({'error': 'No attack logs found'})
        
        # Create ML analyzer
        analyzer = HoneypotMLAnalyzer()
        
        # Generate report
        report = analyzer.generate_attack_pattern_report(attack_logs)
        
        if 'error' in report:
            return jsonify({'error': report['error']})
        
        return jsonify(report)
    
    except Exception as e:
        return jsonify({'error': f'Error generating attack report: {str(e)}'})

@app.route('/api/ml/visualizations', methods=['GET'])
def api_ml_visualizations():
    """Generate visualizations for attack data."""
    try:
        from ml_analyzer import HoneypotMLAnalyzer
        
        attack_logs = get_attack_logs()
        
        if not attack_logs:
            return jsonify({'error': 'No attack logs found'})
        
        # Create ML analyzer
        analyzer = HoneypotMLAnalyzer()
        
        # Generate visualizations
        output_dir = 'static/images/ml'
        visualizations = analyzer.generate_visualizations(attack_logs, output_dir=output_dir)
        
        if 'error' in visualizations:
            return jsonify({'error': visualizations['error']})
        
        # Convert paths to URLs
        visualization_urls = {}
        for name, path in visualizations.items():
            url_path = path.replace('static', '')
            visualization_urls[name] = url_path
        
        return jsonify({
            'visualizations': visualization_urls,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
    
    except Exception as e:
        return jsonify({'error': f'Error generating visualizations: {str(e)}'})

# Register the add_log_entry function to be available to the honeypot module
from honeypot import register_log_callback
register_log_callback(add_log_entry)
