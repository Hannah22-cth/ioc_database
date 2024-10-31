import requests
from bs4 import BeautifulSoup
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
import hashlib
import re
from urllib.parse import urlparse, urljoin
import config
import tldextract
import logging
import ssl
import socket
import whois
from datetime import datetime
import os
from typing import Dict, Any, Tuple, List

# Set up constants
DATASET_PATH = 'Phishing-detection-ML/Generate dataset/dataset'

# Set up logging
logging.basicConfig(filename=config.LOG_FILE, level=config.LOG_LEVEL, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

def get_mongodb_client() -> MongoClient:
    try:
        client = MongoClient(os.environ.get('MONGO_URI', 'mongodb://localhost:27017/'))
        client.admin.command('ismaster')
        return client
    except ConnectionFailure:
        logging.error("MongoDB server not available")
        raise

def check_allowlist(url: str) -> bool:
    allowlisted_urls = set()
    
    # Build the path to the whitelist file
    base_path = os.path.dirname(__file__)
    whitelist_path = os.path.join(base_path, 'Generate dataset/dataset/whitelist.txt')
    
    try:
        with open(whitelist_path, 'r') as file:
            allowlisted_urls = {line.strip() for line in file}
    except FileNotFoundError:
        logging.error("Allowlist file not found.")
    
    domain = tldextract.extract(url).domain
    
    with get_mongodb_client() as client:
        db = client[os.environ.get('MONGO_DB', 'phishing_detection')]
        
        is_allowlisted = url in allowlisted_urls
        is_majestic = db[config.COLLECTIONS['majestic_million']].find_one({"domain": domain}) is not None
        
        logging.info(f"Allowlist check for {url}: {'allowlisted' if is_allowlisted else 'not allowlisted'}, majestic: {'yes' if is_majestic else 'no'}")
        
        return is_allowlisted or is_majestic

def check_iocs(domain: str, file_hash: str, file_name: str, keyword: str, ip_address: str) -> Dict[str, bool]:
    with get_mongodb_client() as client:
        db = client[os.environ.get('MONGO_DB', 'phishing_detection')]
        results = {
            "domain": False,
            "file_hash": False,
            "file_name": False,
            "keyword": False,
            "ip_address": False
        }
        
        if domain:
            results["domain"] = db[config.COLLECTIONS['domains']].find_one({"domain": domain, "is_malicious": True}) is not None
            logging.info(f"Checked domain IOC for {domain}: {'malicious' if results['domain'] else 'clean'}")
        
        if file_hash:
            results["file_hash"] = db[config.COLLECTIONS['file_hashes']].find_one({"hash": file_hash, "is_malicious": True}) is not None
            logging.info(f"Checked file hash IOC for {file_hash}: {'malicious' if results['file_hash'] else 'clean'}")
        
        if file_name:
            results["file_name"] = db[config.COLLECTIONS['file_names']].find_one({"name": file_name, "is_malicious": True}) is not None
            logging.info(f"Checked file name IOC for {file_name}: {'malicious' if results['file_name'] else 'clean'}")
        
        if keyword:
            results["keyword"] = db[config.COLLECTIONS['keywords']].find_one({"word": keyword, "is_malicious": True}) is not None
            logging.info(f"Checked keyword IOC for {keyword}: {'malicious' if results['keyword'] else 'clean'}")
        
        if ip_address:
            results["ip_address"] = db[config.COLLECTIONS['ip_addresses']].find_one({"address": ip_address, "is_malicious": True}) is not None
            logging.info(f"Checked IP address IOC for {ip_address}: {'malicious' if results['ip_address'] else 'clean'}")
        
        return results

def analyze_dom(html_content: str, base_url: str) -> List[str]:
    alerts = []
    soup = BeautifulSoup(html_content, 'html.parser')
    
    iocs = {
        "file_names": ["app.35972da7.css"],
        "file_hashes": ["5ee8de0a03d3c12c09ee9c94f31b493fafda20761e6dc6fe58d916d31bdb909b"],
        "keywords": ["mihuangame"]
    }

    for elem in soup.find_all(['script', 'link', 'img'], src=True):
        src = urljoin(base_url, elem['src'])
        file_name = os.path.basename(urlparse(src).path)
        if file_name in iocs["file_names"]:
            alert_message = f"Detected malicious file name in DOM: {file_name}"
            alerts.append(alert_message)
            logging.warning(alert_message)
        
        try:
            file_content = requests.get(src).content
            file_hash = hashlib.sha256(file_content).hexdigest()
            if file_hash in iocs["file_hashes"]:
                alert_message = f"Detected malicious file hash in DOM: {file_hash} for file {file_name}"
                alerts.append(alert_message)
                logging.warning(alert_message)
        except requests.RequestException:
            logging.warning(f"Failed to fetch file content from {src}")

    text_content = soup.get_text().lower()
    for keyword in text_content.split():
        if keyword in iocs["keywords"]:
            alert_message = f"Detected suspicious keyword in DOM content: {keyword}"
            alerts.append(alert_message)
            logging.warning(alert_message)

    return alerts

def analyze_http_transaction(headers: Dict[str, str], content: str) -> List[str]:
    alerts = []
    
    iocs = {
        "file_names": ["app.35972da7.css"],
        "file_hashes": ["5ee8de0a03d3c12c09ee9c94f31b493fafda20761e6dc6fe58d916d31bdb909b"],
        "keywords": ["mihuangame"]
    }

    content_hash = hashlib.sha256(content.encode()).hexdigest()
    if content_hash in iocs["file_hashes"]:
        alert_message = f"Detected malicious file hash in HTTP content: {content_hash}"
        alerts.append(alert_message)
        logging.warning(alert_message)

    for header, value in headers.items():
        if header.lower() in ['content-disposition', 'location']:
            file_name = os.path.basename(urlparse(value).path)
            if file_name in iocs["file_names"]:
                alert_message = f"Detected malicious file name in HTTP header {header}: {file_name}"
                alerts.append(alert_message)
                logging.warning(alert_message)

    for keyword in content.lower().split():
        if keyword in iocs["keywords"]:
            alert_message = f"Detected suspicious keyword in HTTP content: {keyword}"
            alerts.append(alert_message)
            logging.warning(alert_message)
    
    return alerts

def check_ssl_cert(url: str) -> Tuple[bool, str]:
    try:
        hostname = urlparse(url).netloc
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                cert = secure_sock.getpeercert()
                
        subject = dict(x[0] for x in cert['subject'])
        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        
        if not_after < datetime.now():
            return False, "SSL certificate has expired"
        if subject['commonName'] != hostname:
            return False, "SSL certificate doesn't match hostname"
        
        return True, "Valid SSL certificate"
    except Exception as e:
        return False, f"SSL certificate error: {str(e)}"

def check_domain_age(url: str) -> int:
    try:
        domain = tldextract.extract(url).registered_domain
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age = (datetime.now() - creation_date).days
        logging.info(f"Checked domain age for {domain}: {age} days")
        return age
    except Exception as e:
        logging.error(f"Error checking domain age: {str(e)}")
        return None

def scan_url(url: str) -> str:
    logging.info(f"Starting scan for URL: {url}")

    # Ensure the URL has a scheme
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url  # Add HTTPS scheme by default

    if check_allowlist(url):
        logging.info(f"URL {url} is allowlisted. Skipping further checks.")
        return "100% safe"

    try:
        response = requests.get(url, timeout=10)
        html_content = response.text
        headers = dict(response.headers)
        content = response.content.decode('utf-8', errors='ignore')
        
        dom_alerts = analyze_dom(html_content, url)
        http_alerts = analyze_http_transaction(headers, content)
        
        ssl_valid, ssl_message = check_ssl_cert(url)
        domain_age = check_domain_age(url)
        
        all_alerts = dom_alerts + http_alerts
        if not ssl_valid:
            all_alerts.append(ssl_message)
        if domain_age is not None and domain_age < 30:
            alert_message = f"Domain is only {domain_age} days old"
            all_alerts.append(alert_message)
            logging.warning(alert_message)
        
        is_malicious = any([any(dom_alerts), any(http_alerts)])
        
        if is_malicious:
            logging.warning(f"Scan completed for {url}: 100% malicious. Alerts: {all_alerts}")
            return "100% malicious"
        
        logging.info(f"Scan completed for {url}: 100% safe")
        return "100% safe"
    
    except requests.RequestException as e:
        logging.error(f"Error fetching URL {url}: {str(e)}")
        return f"Error fetching URL: {str(e)}"

if __name__ == "__main__":
    url = input("Enter a URL to scan: ")
    result = scan_url(url)
    print(result)
