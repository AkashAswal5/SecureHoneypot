import os
import logging
import requests
import geoip2.database
from geoip2.errors import AddressNotFoundError
import tempfile
import shutil

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# GeoLite2 database paths
GEOLITE_CITY_DB_PATH = "GeoLite2-City.mmdb"
GEOLITE_ASN_DB_PATH = "GeoLite2-ASN.mmdb"

def download_geolite_db():
    """
    Download the GeoLite2 City and ASN databases if they don't exist.
    
    In a real-world scenario, you would download these from MaxMind with a license key.
    For this project, we'll use a placeholder approach to create the DB files.
    """
    try:
        # Check if databases already exist
        if os.path.exists(GEOLITE_CITY_DB_PATH) and os.path.exists(GEOLITE_ASN_DB_PATH):
            logger.info("GeoLite2 databases already exist")
            return True
        
        logger.info("GeoLite2 databases not found. Please obtain them from MaxMind.")
        logger.info("Visit: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
        
        # Return False to indicate that the databases need to be provided
        return False
        
    except Exception as e:
        logger.error(f"Error downloading GeoLite2 databases: {e}")
        return False

def get_ip_location(ip_address):
    """
    Get geolocation information for an IP address.
    
    Args:
        ip_address (str): The IP address to look up
        
    Returns:
        dict: Geolocation information including country, city, coordinates, ISP, etc.
    """
    # Default empty location data
    location_data = {
        'country': 'Unknown',
        'country_code': 'XX',
        'city': 'Unknown',
        'latitude': 0,
        'longitude': 0,
        'isp': 'Unknown',
        'asn': 'Unknown'
    }
    
    # Check for private/reserved IP addresses
    if ip_address.startswith(('10.', '192.168.', '127.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '169.254.')):
        location_data['country'] = 'Private IP'
        location_data['city'] = 'Local Network'
        return location_data
    
    try:
        # First, try to use the local GeoLite2 databases if available
        if os.path.exists(GEOLITE_CITY_DB_PATH) and os.path.exists(GEOLITE_ASN_DB_PATH):
            # Get city/country info
            with geoip2.database.Reader(GEOLITE_CITY_DB_PATH) as city_reader:
                city_response = city_reader.city(ip_address)
                location_data['country'] = city_response.country.name or 'Unknown'
                location_data['country_code'] = city_response.country.iso_code or 'XX'
                location_data['city'] = city_response.city.name or 'Unknown'
                location_data['latitude'] = city_response.location.latitude or 0
                location_data['longitude'] = city_response.location.longitude or 0
            
            # Get ISP/ASN info
            with geoip2.database.Reader(GEOLITE_ASN_DB_PATH) as asn_reader:
                asn_response = asn_reader.asn(ip_address)
                location_data['asn'] = f"AS{asn_response.autonomous_system_number}" if asn_response.autonomous_system_number else 'Unknown'
                location_data['isp'] = asn_response.autonomous_system_organization or 'Unknown'
        
        else:
            # If local databases are not available, try using a free API service
            response = requests.get(f"https://ipapi.co/{ip_address}/json/", timeout=5)
            if response.status_code == 200:
                api_data = response.json()
                location_data['country'] = api_data.get('country_name', 'Unknown')
                location_data['country_code'] = api_data.get('country_code', 'XX')
                location_data['city'] = api_data.get('city', 'Unknown')
                location_data['latitude'] = api_data.get('latitude', 0)
                location_data['longitude'] = api_data.get('longitude', 0)
                location_data['isp'] = api_data.get('org', 'Unknown')
                location_data['asn'] = api_data.get('asn', 'Unknown')
            
    except AddressNotFoundError:
        logger.warning(f"IP address {ip_address} not found in GeoIP database")
    except Exception as e:
        logger.error(f"Error getting location for IP {ip_address}: {e}")
    
    return location_data

def get_ip_threat_intel(ip_address):
    """
    Get threat intelligence information for an IP address.
    
    Args:
        ip_address (str): The IP address to look up
        
    Returns:
        dict: Threat intel information including risk score and threat classification
    """
    # Default threat intel data
    threat_intel = {
        'risk_score': 0,
        'is_known_attacker': False,
        'threat_type': 'None',
        'last_seen': 'Never'
    }
    
    # Check for private/reserved IP addresses
    if ip_address.startswith(('10.', '192.168.', '127.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '169.254.')):
        return threat_intel
    
    try:
        # Try to get threat intel from AbuseIPDB API if API key is available
        api_key = os.environ.get('ABUSEIPDB_API_KEY')
        if api_key:
            headers = {
                'Accept': 'application/json',
                'Key': api_key
            }
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90
            }
            
            response = requests.get('https://api.abuseipdb.com/api/v2/check', 
                                   headers=headers, 
                                   params=params)
            
            if response.status_code == 200:
                result = response.json()
                data = result.get('data', {})
                
                threat_intel['risk_score'] = data.get('abuseConfidenceScore', 0)
                threat_intel['is_known_attacker'] = data.get('abuseConfidenceScore', 0) > 50
                threat_intel['last_seen'] = data.get('lastReportedAt', 'Never')
                
                # Classify the threat based on category codes
                categories = data.get('reports', [])
                if categories:
                    if 14 in categories or 15 in categories or 16 in categories:
                        threat_intel['threat_type'] = 'Port Scanner'
                    elif 18 in categories or 21 in categories:
                        threat_intel['threat_type'] = 'Web Attack'
                    elif 23 in categories:
                        threat_intel['threat_type'] = 'SSH Attack'
                    elif 4 in categories or 10 in categories:
                        threat_intel['threat_type'] = 'Brute Force'
                    else:
                        threat_intel['threat_type'] = 'Suspicious Activity'
    
    except Exception as e:
        logger.error(f"Error getting threat intel for IP {ip_address}: {e}")
    
    return threat_intel