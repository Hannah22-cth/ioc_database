#!/usr/bin/env python
"""
This is the Flask REST API that processes and outputs the prediction on the URL.
"""
import os
import json
import time
import glob
import hashlib
import logging
import re
from datetime import datetime
from typing import Dict, Any, List, Tuple

import numpy as np
import pandas as pd
import tensorflow as tf
import seaborn as sns
import matplotlib
import matplotlib.cm as cm
from matplotlib.colors import Normalize
from matplotlib import colors

from flask import Flask, redirect, url_for, render_template, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename

from pymongo import MongoClient
from bson import ObjectId

import joblib
import pickle
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.preprocessing.text import Tokenizer

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import tldextract
import ssl
import socket
import whois

from dotenv import load_dotenv
from model import ConvModel
import config
from url_scanner import scan_url, check_allowlist, check_iocs, analyze_dom, analyze_http_transaction, check_ssl_cert, check_domain_age

# Load environment variables
load_dotenv()

MONGODB = os.getenv('MONGODB')

# Disable GPU for TensorFlow
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"

# Flask app initialization
app = Flask(__name__)
app.config["CACHE_TYPE"] = "null"
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# MongoDB setup
client = MongoClient(config.MONGO_URI)
db = client[config.MONGO_DB]

# Load ML model and tokenizer
with open('tokenizer.pickle', 'rb') as handle:
    tokenizer = pickle.load(handle)
num_chars = len(tokenizer.word_index) + 1
embedding_vector_length = 128
maxlen = 128
max_words = 20000

with tf.device('/cpu:0'):
    model_pre = "./checkpointModel/bestModelCNN"
    model = ConvModel(num_chars, embedding_vector_length, maxlen)
    model.built = True
    model.load_weights(model_pre)

# Load country mapping
country_mapping = {}
country2digit = pd.read_csv("country_mapping.csv")
for idx, _country in enumerate(country2digit['Code']):
    country_mapping[_country] = country2digit['Name'][idx]

# Utility functions
def hex_color():
    color_list = []
    colors_data = np.random.randn(10, 10)
    cmap = cm.get_cmap('Blues')
    norm = Normalize(vmin=colors_data.min(), vmax=colors_data.max())
    rgba_values = cmap(norm(colors_data))
    for layer1 in rgba_values:
        for layer2 in layer1:
            color_list.append(colors.to_hex([layer2[0], layer2[1], layer2[2]]))
    return color_list

def preprocess_url(url, tokenizer):
    url = url.strip()
    sequences = tokenizer.texts_to_sequences([url])
    word_index = tokenizer.word_index
    url_prepped = pad_sequences(sequences, maxlen=maxlen)
    return url_prepped

def extract_features(url, html_content):
    features = {}
    features['url_length'] = len(url)
    features['domain_length'] = len(urlparse(url).netloc)
    features['num_subdomains'] = len(urlparse(url).netloc.split('.')) - 1
    features['has_ip'] = int(bool(re.match(r'\d+\.\d+\.\d+\.\d+', urlparse(url).netloc)))
    features['has_at_symbol'] = int('@' in url)
    features['has_double_slash'] = int('//' in url.split('://')[1])
    
    soup = BeautifulSoup(html_content, 'html.parser')
    features['num_iframes'] = len(soup.find_all('iframe'))
    features['num_scripts'] = len(soup.find_all('script'))
    features['num_hidden_elements'] = len(soup.find_all(style=re.compile(r'display:\s*none')))
    features['num_external_links'] = len([a for a in soup.find_all('a', href=True) if a['href'].startswith('http')])
    
    return features

# Route handlers
@app.route('/', methods=["GET", "POST"])
def survey():
    features = {
        'Speical_Char': 'Number of Speicial Character in URL like ~,!,@,#,$,%,^,&,*,...',
        'Have_IP': 'Checks if IP address in URL',
        'Have_At': 'Checks the presence of @ in URL',
        'URL_length': 'Finding the length of URL and categorizing',
        'URL_Depth': 'Gives number of / in URL',
        'redirection': 'Checking for redirection // in the URL',
        'time_get_redirect': 'Number of time get redirect after click URL',
        'port_in_url': 'Suspicous port appear in the URL',
        'use_http': 'Use HTTP insted of HTTPS',
        'http_in_domain': 'HTTP(S) in the URL (example: https://report?https://reportId=https://QYJT9PC9YPFTDC7JJ&https://reportType=https://question)',
        'TinyURL': 'Checking for Shortening Services in URL',
        'Prefix/Suffix': 'Checking for Prefix or Suffix Separated by (-) in the URL',
        'DNS_Record': 'Check if the DNS record A point to the right Website',
        'trusted_ca': 'Checking if the Certificate provide by trusted provider like cPanel,Microsoft,Go,DigiCert,...',
        'domain_lifespan': 'Checking if Life span of domain under 6 months',
        'domain_timeleft': 'Checking if time left of domain under 6 months',
        'same_asn': 'Check if others server like Domain, Dns Server,... on the same IP',
        'iFrame': 'Check if Iframe Function in Web content',
        'Mouse_Over': 'Check if Mouse_Over Function in Web content',
        'Right_Click': 'Check if Right_Click Function in Web content',
        'Web_Forwards': 'Checks the number of forwardings in Web content',
        'eval': 'Check if Eval Function in Web content',
        'unescape': 'Check if Unescape Function in Web content',
        'escape': 'Check if Escape Function in Web content',
        'ActiveXObject': 'Check if ActiveXObject Function in Web content',
        'fromCharCode': 'Check if fromCharCode Function in Web content',
        'atob': 'Check if atob Function in Web content',
        'Punny_Code': 'Check if punny code in URL'
    }
    sublist = [list(features.keys())[n:n+3] for n in range(0, len(list(features.keys())), 3)]
    
    if request.method == "POST" and request.form['url'] != None:
        url = request.form['url']
        if url == '':
            return jsonify({'notvalid': 'Maybe your input not correct'})
        
        print(url)
        if isinstance(url, str):
            url_prepped = preprocess_url(url, tokenizer)
            prediction = model.predict(url_prepped)
            
            if prediction > 0.5:
                return jsonify({'notsafe': 'Website Phishing', 'score': str(prediction[0][0])})
            else:
                return jsonify({'safe': 'Website Legitimate', 'score': str(prediction[0][0])})
    
    return render_template('index.html', data=sublist, features=features)

@app.route('/dashboard', methods=["GET", "POST"])
def dashboard():
    country_data = []
    contry_pipeline = [
        {'$group': {'_id': '$country_name', 'count': {'$sum': 1}}},
        {'$sort': {'count': -1}}
    ]
    TLDs_pipeline = [
        {'$group': {'_id': '$TLDs', 'count': {'$sum': 1}}},
        {'$sort': {'count': -1}},
        {'$limit': 10}
    ]
    Title_pipeline = [
        {'$group': {'_id': '$Title', 'count': {'$sum': 1}}},
        {'$sort': {'count': -1}},
        {'$limit': 10}
    ]

    total = db['DATA'].count_documents({})
    contry_query = list(db['DATA'].aggregate(contry_pipeline))
    top_country = list(contry_query)
    colors = hex_color()

    start = 0
    if top_country[0]['_id'] == None:
        start = 1
    top_country = top_country[start:start+len(colors)]

    for idx, _data in enumerate(colors):
        try:
            country_dict = {
                'id': top_country[idx]['_id'],
                'name': country_mapping[top_country[idx]['_id']],
                'value': top_country[idx]['count'],
                'fill': _data
            }
            country_data.append(country_dict)
        except:
            continue

    top_tlds = list(db['DATA'].aggregate(TLDs_pipeline))
    top_title = list(db['DATA'].aggregate(Title_pipeline))
    Importances = list(db["Models"].find({}, {"_id": 0}))

    url_based = ['Speical_Char', 'URL_Depth', 'use_http', 'redirection', 'URL_length', 'time_get_redirect', 'Prefix/Suffix', 'TinyURL', 'port_in_url', 'Have_At', 'http_in_domain', 'Have_IP', 'Punny_Code']
    domain_based = ['same_asn', 'domain_lifespan', 'domain_timeleft', 'DNS_Record', 'trusted_ca']
    content_based = ['iFrame', 'Web_Forwards', 'Mouse_Over', 'Right_Click', 'fromCharCode', 'ActiveXObject', 'escape', 'eval', 'atob', 'unescape']
    percent_list = []

    for _features in (url_based, domain_based, content_based):
        percent = sum(Importances[0][i] for i in _features)
        percent_list.append(percent * 100)

    return render_template('dashboard.html', country_data=country_data, top_tlds=top_tlds, top_title=top_title, Importances=Importances[0], url_based=url_based, domain_based=domain_based, content_based=content_based, percent_list=percent_list)

@app.route('/comparison', methods=["GET", "POST"])
def comparison():
    if request.method == 'POST':
        f = request.files['file']
        _DATA = list()

        if f:
            for _ in glob.glob(UPLOAD_FOLDER + "/*.csv"):
                os.remove(_)
            filename = secure_filename(f.filename)
            f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            df = pd.read_csv(UPLOAD_FOLDER + '/' + filename)

            for idx, value in enumerate(df['url']):
                url_prepped = preprocess_url(value, tokenizer)
                prediction = model.predict(url_prepped)
                
                your_model = "&#10008" if prediction > 0.5 else "&#10004"
                cld_model = "&#10008" if df['labels'][idx] == 1 else "&#10004"
                _DATA.append((cld_model, value, your_model))

            ls = [_[0] for _ in _DATA]
            return str(ls)
    else:
        df = pd.read_csv(UPLOAD_FOLDER + '/testing.csv')
        data = list(df['labels'])
        return render_template('dashboard-model.html', data=data)

@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    if request.method == "POST":
        today = datetime.utcfromtimestamp(int(time.time())).strftime('%Y-%m-%d %H:%M:%S')
        data = {
            "Date": today,
            "Title": request.form['title'],
            "Content": request.form['content'],
        }
        json_object = json.dumps(data, indent=4)
        with open('feedback/' + str(time.time()) + "_feedback.json", "w") as f:
            f.write(json_object)
        return jsonify(success=True)

@app.route("/predict", methods=["GET", "POST"])
def predict():
    data = {"success": False}
    if request.method == "POST":
        start = time.time()
        incoming = request.get_json()
        url = incoming["url"]

        if url == '':
            return jsonify({'message': 'Maybe your input not correct'})

        data["predictions"] = []
        if isinstance(url, str):
            url_prepped = preprocess_url(url, tokenizer)
            prediction = model.predict(url_prepped)
            end = time.time() - start
            
            result = "URL is probably phishing" if prediction > 0.5 else "URL is probably NOT phishing"
            prediction = float(prediction) * 100
            
            r = {"result": result, "phishing percentage": prediction, "url": url}
            data["predictions"].append(r)
            data["success"] = True
            data["time_elapsed"] = end

        return jsonify(data)
    else:
        return jsonify({'message': 'Send me something'})

@app.route('/api/analyze', methods=['POST'])
@limiter.limit("10 per minute")
def analyze_url():
    url = request.json.get('url')
    if not url:
        return jsonify({"error": "URL is required"}), 400
    
    try:
        scan_result = scan_url(url)
        
        if scan_result.get("is_allowlisted"):
            return jsonify({
                "url": url,
                "is_safe": True,
                "confidence": 1.0,
                "message": "URL is in the allowlist and considered safe."
            })
        
        if scan_result.get("error"):
            return jsonify({"error": scan_result["error"]}), 500
        
        if scan_result["is_malicious"]:
            return jsonify({
                "url": url,
                "is_safe": False,
                "confidence": 1.0,
                
                "message": "URL contains known malicious indicators.",
                "alerts": scan_result["alerts"]
            })
        
        response = requests.get(url, timeout=10)
        html_content = response.text
        
        features = extract_features(url, html_content)
        prediction = model.predict_proba([features])[0][1]  # Assuming binary classification
        
        is_safe = not scan_result["is_suspicious"] and prediction <= config.PHISHING_SCORE_THRESHOLD
        
        result = {
            "url": url,
            "is_safe": is_safe,
            "confidence": float(1 - prediction) if is_safe else float(prediction),
            "alerts": scan_result["alerts"],
            "ssl_valid": scan_result["ssl_valid"],
            "domain_age": scan_result["domain_age"],
            "timestamp": datetime.now().isoformat()
        }
        
        # Log the analysis result
        db[config.COLLECTIONS['update_logs']].insert_one(result)
        
        return jsonify(result)
    
    except requests.RequestException as e:
        return jsonify({"error": f"Error fetching URL: {str(e)}"}), 500

@app.route('/api/ioc/<ioc_type>', methods=['GET', 'POST'])
@limiter.limit("100 per hour")
def manage_ioc(ioc_type):
    if ioc_type not in config.COLLECTIONS:
        return jsonify({"error": "Invalid IOC type"}), 400
    
    collection = db[config.COLLECTIONS[ioc_type]]
    
    if request.method == 'GET':
        iocs = list(collection.find({}, {'_id': 0}))
        return jsonify(iocs)
    
    elif request.method == 'POST':
        new_ioc = request.json
        result = collection.insert_one(new_ioc)
        return jsonify({"message": "IOC added successfully", "id": str(result.inserted_id)}), 201

@app.route('/api/ioc/<ioc_type>/<ioc_id>', methods=['PUT', 'DELETE'])
@limiter.limit("100 per hour")
def manage_single_ioc(ioc_type, ioc_id):
    if ioc_type not in config.COLLECTIONS:
        return jsonify({"error": "Invalid IOC type"}), 400
    
    collection = db[config.COLLECTIONS[ioc_type]]
    
    if request.method == 'PUT':
        update_data = request.json
        result = collection.update_one({"_id": ObjectId(ioc_id)}, {"$set": update_data})
        if result.modified_count:
            return jsonify({"message": "IOC updated successfully"})
        return jsonify({"error": "IOC not found"}), 404
    
    elif request.method == 'DELETE':
        result = collection.delete_one({"_id": ObjectId(ioc_id)})
        if result.deleted_count:
            return jsonify({"message": "IOC deleted successfully"})
        return jsonify({"error": "IOC not found"}), 404

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": "Rate limit exceeded"}), 429

if __name__ == "__main__":
    print("Starting the server and loading the model...")
    app.run(host=config.API_HOST, port=config.API_PORT, debug=config.DEBUG)