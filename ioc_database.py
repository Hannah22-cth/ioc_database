from pymongo import MongoClient
import os
import logging

# MongoDB connection parameters
MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')
DATABASE_NAME = os.environ.get('MONGO_DB', 'phishing_detection')

def get_database():
    """Connect to MongoDB and return the database instance."""
    try:
        client = MongoClient(MONGO_URI)
        return client[DATABASE_NAME]
    except Exception as e:
        print(f"Could not connect to MongoDB: {str(e)}")
        raise

def check_indicator_in_collections(indicator: str) -> str:
    """Check if the indicator exists in any of the collections."""
    db = get_database()
    
    # Check if indicator is in allowlist or whitelist (100% safe)
    if db.allowlist.find_one({"url": indicator}) or db.whitelist.find_one({"url": indicator}):
        return "100% safe"
    
    # Check if indicator is in the keywords collection (malicious)
    if db.keywords.find_one({"keyword": indicator}):
        return "100% malicious"
    
    # Check other collections for malicious indicators
    if (db.blacklist.find_one({"url": indicator}) or 
        db.iocs.find_one({"url": indicator}) or 
        db.domains.find_one({"domain": indicator}) or 
        db.file_hashes.find_one({"hash": indicator}) or 
        db.file_names.find_one({"name": indicator}) or 
        db.ip_addresses.find_one({"address": indicator})):
        return "100% malicious"
    
    return "potentially unsafe"

def scan_indicator(indicator: str) -> str:
    """Scan the provided indicator and return its status."""
    return check_indicator_in_collections(indicator)

if __name__ == "__main__":
    try:
        indicator = input("Enter an indicator to scan: ")
        result_status = scan_indicator(indicator)
        
        print(f"\nScan Results for {indicator}:")
        print(f"Status: {result_status}")
        
    except EOFError:
        print("Input was interrupted.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")
