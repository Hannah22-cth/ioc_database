import os
from pathlib import Path

# Base directories
BASE_DIR = Path(__file__).resolve().parent
DATASET_DIR = BASE_DIR / 'Generate Dataset' / 'dataset'

# MongoDB configuration
MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')
MONGO_DB = os.environ.get('MONGO_DB', 'phishing_detection')

# Collections
COLLECTIONS = {
    'domains': 'domains',
    'file_hashes': 'file_hashes',
    'file_names': 'file_names',
    'keywords': 'keywords',
    'ip_addresses': 'ip_addresses',
    'update_logs': 'update_logs',
    'phishtank': 'phishtank',
    'top500domains': 'top500domains',
    'urlset': 'urlset',
    'dataset': 'dataset',
    'chongluadao': 'chongluadao',
    'majestic_million': 'majestic_million',
    'phish_score': 'phish_score',
    'phishstats': 'phishstats',
    'blacklist': 'blacklist',
    'whitelist': 'whitelist'
}

# File paths
FILE_HASHES_FILE = DATASET_DIR / 'file_hashes.csv' 
PHISHTANK_V1_FILE = DATASET_DIR / 'phishtank.csv'
PHISHTANK_V2_FILE = DATASET_DIR / 'phishtankv2.csv'
TOP500DOMAINS_FILE = DATASET_DIR / 'top500Domains.csv'
URLSET_FILE = DATASET_DIR / 'urlset.csv'
TRAINING_DATASET_FILE = DATASET_DIR / 'Training Dataset.arff'
WHITELIST_FILE = DATASET_DIR / 'whitelist.txt'
CHONGLUADAOV2_FILE = DATASET_DIR / 'chongluadaov2.csv'
MAJESTIC_MILLION_FILES = [DATASET_DIR / f'majestic_million-{i:03d}.csv' for i in range(11)]
MODIFY_DATASET_FILE = DATASET_DIR / 'modify_dataset.csv'
PHISH_SCORE_FILE = DATASET_DIR / 'phish_score.csv'
PHISHSTATS_FILE = DATASET_DIR / 'phishstats.csv'
PHISHTANK_FILE = DATASET_DIR / 'phishtank.csv'
BLACKLIST_FILE = DATASET_DIR / 'blacklist.txt'
HELLBLACKLIST_FILE = DATASET_DIR / 'hellblacklist.txt'
HELLPHISHING_FILE = DATASET_DIR / 'hellphishing.txt'
PHISHING_FILE = DATASET_DIR / 'phishing.txt'

# Model files
MODEL_FILE = BASE_DIR / 'rf_final.pkl'
TOKENIZER_FILE = BASE_DIR / 'tokenizer.pickle'

# Logging
LOG_FILE = BASE_DIR / 'phishing_detection.log'
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')

# API configuration
API_HOST = os.environ.get('API_HOST', '0.0.0.0')
API_PORT = int(os.environ.get('API_PORT', 5000))
DEBUG = bool(os.environ.get('DEBUG', True))

# Update schedule
UPDATE_INTERVAL = 24  # hours

# Phishing detection thresholds
PHISHING_SCORE_THRESHOLD = 0.7
ALERT_THRESHOLD = 3

def validate_config():
    """Validate the configuration settings"""
    for file_path in [
        PHISHTANK_V1_FILE, PHISHTANK_V2_FILE, TOP500DOMAINS_FILE, URLSET_FILE,
        TRAINING_DATASET_FILE,
        WHITELIST_FILE,  CHONGLUADAOV2_FILE,
        MODIFY_DATASET_FILE, PHISH_SCORE_FILE, PHISHSTATS_FILE, PHISHTANK_FILE,
        BLACKLIST_FILE, HELLBLACKLIST_FILE, HELLPHISHING_FILE, PHISHING_FILE,
        MODEL_FILE, TOKENIZER_FILE,  
    ] + MAJESTIC_MILLION_FILES:
        if not file_path.exists():
            print(f"Warning: Required file not found: {file_path}")

validate_config()

