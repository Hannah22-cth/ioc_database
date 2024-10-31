import os
import pandas as pd
from pymongo import MongoClient
import chardet

# Define the base path for datasets and the files to import
BASE_PATH = os.path.join(os.path.dirname(__file__), 'Generate dataset', 'dataset')

# Mapping of files to their corresponding MongoDB collections
FILE_COLLECTION_MAP = {
    'whitelist.txt': 'whitelist',
    'phishtank.csv': 'urls',
    'phishtankv1.csv': 'urls',
    'phishtankv2.csv': 'urls',
    'majestic_million-000.csv': 'domains',
    'majestic_million-001.csv': 'domains',
    'majestic_million-002.csv': 'domains',
    'majestic_million-003.csv': 'domains',
    'majestic_million-004.csv': 'domains',
    'majestic_million-005.csv': 'domains',
    'majestic_million-006.csv': 'domains',
    'majestic_million-007.csv': 'domains',
    'majestic_million-008.csv': 'domains',
    'majestic_million-009.csv': 'domains',
    'majestic_million-010.csv': 'domains',
    'urlset.csv': 'features',
    'top500Domains.csv': 'domains',
    'phishing.txt': 'keywords',
    'phishstats.txt': 'stats',
    'Training Dataset.arff': 'training_data',
    'chongluadaov2.csv': 'chongluadao',
    'list.txt': 'lists',
    'hellphishing.txt': 'keywords',
    'blacklist.csv': 'blacklist',
    'hellblacklist.txt': 'blacklist',
    'modify_dataset.csv': 'modify_data',
    'phishstats.csv': 'stats',
    'phish_score.csv': 'stats'
}

def import_datasets():
    client = MongoClient('mongodb://localhost:27017/')
    db = client['phishing_detection']

    for file_name, collection_name in FILE_COLLECTION_MAP.items():
        file_path = os.path.join(BASE_PATH, file_name)
        if os.path.exists(file_path):
            try:
                with open(file_path, 'rb') as f:
                    result = chardet.detect(f.read())
                encoding = result['encoding']
                print(f"Detected encoding for {file_name}: {encoding}")

                # Determine if records exist in the collection
                existing_records = db[collection_name].count_documents({})

                if file_name.endswith('.csv'):
                    data = pd.read_csv(file_path, encoding=encoding, on_bad_lines='skip', low_memory=False)

                elif file_name.endswith('.txt'):
                    with open(file_path, 'r', encoding=encoding) as f:
                        data = f.readlines()
                        data = [{'keyword': line.strip()} for line in data if line.strip()]

                if isinstance(data, pd.DataFrame):
                    if not data.empty:
                        # Only insert if there are no existing records
                        if existing_records == 0:
                            db[collection_name].insert_many(data.to_dict('records'))
                            print(f"Imported {file_name} into {collection_name} successfully.")
                        else:
                            print(f"{file_name} already exists in {collection_name}. Skipping import.")
                    else:
                        print(f"{file_name} is empty. Skipping import.")
                elif isinstance(data, list) and data:
                    if existing_records == 0:
                        db[collection_name].insert_many(data)
                        print(f"Imported {file_name} into {collection_name} successfully.")
                    else:
                        print(f"{file_name} already exists in {collection_name}. Skipping import.")
                else:
                    print(f"{file_name} is empty or invalid. Skipping import.")

            except Exception as e:
                print(f"Error reading {file_name}: {e}")
        else:
            print(f"File {file_name} not found in the dataset directory.")

if __name__ == "__main__":
    import_datasets()
