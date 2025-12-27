from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import os
from datetime import datetime
from io import BytesIO
import requests
from urllib.parse import urlparse
import validators
import numpy as np
from PIL import Image
import cv2
import tensorflow as tf
from tensorflow.keras.models import load_model
import time

# ----------------------------
# Flask App Initialization
# ----------------------------
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload
app.config['UPLOAD_FOLDER'] = 'temp_uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp'}
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ----------------------------
# Load Model
# ----------------------------
START_TIME = time.time()
MODEL_PATH = "final_url_classifier.h5"

try:
    model = tf.keras.models.load_model(MODEL_PATH)
    MODEL_LOADED = True
    print(" Model loaded successfully")
except Exception as e:
    model = None
    MODEL_LOADED = False
    print(" Model load failed:", e)

# ----------------------------
# Helpers
# ----------------------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_qr_data(image_path_or_url):
    try:
        # Open image
        if image_path_or_url.startswith(('http://', 'https://')):
            response = requests.get(image_path_or_url, timeout=10)
            img = Image.open(BytesIO(response.content))
        else:
            img = Image.open(image_path_or_url)

        img_cv = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)

        # Detect QR codes
        detector = cv2.QRCodeDetector()
        data, points, _ = detector.detectAndDecodeMulti(img_cv)
        results = []

        if points is not None and data:
            for i, qr_data in enumerate(data):
                if qr_data:
                    is_url = validators.url(qr_data)
                    polygon = points[i].tolist()
                    x, y, w, h = cv2.boundingRect(points[i].astype(int))
                    results.append({
                        'data': qr_data,
                        'type': 'url' if is_url else 'text',
                        'rect': {'x': x, 'y': y, 'w': w, 'h': h},
                        'polygon': polygon
                    })
            return {'success': True, 'results': results, 'message': f'Found {len(results)} QR code(s)'}
        else:
            return {'success': False, 'message': 'No QR code found in image'}

    except Exception as e:
        return {'success': False, 'message': f'Error processing image: {str(e)}'}

def preprocess_url_for_model(url):
    features = []
    features.append(len(url))  # URL length
    special_chars = ['@', '!', '#', '$', '%', '&', '*', '(', ')']
    features.append(sum([1 for c in url if c in special_chars]))
    import re
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    features.append(1 if re.search(ip_pattern, url) else 0)
    parsed_url = urlparse(url)
    features.append(parsed_url.netloc.count('.') - 1)  # subdomains
    features.append(1 if parsed_url.scheme == 'https' else 0)
    features.append(len([seg for seg in parsed_url.path.split('/') if seg]))
    features = np.array(features).reshape(1, -1)
    features = features / np.array([200, 10, 1, 5, 1, 10])
    return features

def predict_url(url):
    if model is None:
        return {'success': False, 'error': 'Model not loaded'}
    try:
        features = preprocess_url_for_model(url)
        prediction = model.predict(features, verbose=0)
        confidence = float(prediction[0][0])
        is_malicious = confidence > 0.5
        return {
            'success': True,
            'url': url,
            'is_malicious': bool(is_malicious),
            'confidence': confidence,
            'prediction': 'malicious' if is_malicious else 'benign',
            'risk_level': 'High' if confidence > 0.7 else 'Medium' if confidence > 0.4 else 'Low'
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}

# ----------------------------
# Routes
# ----------------------------
@app.route('/')
def home():
    return jsonify({'message': 'QR Code Malicious URL Detection API'})

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'model_loaded': MODEL_LOADED,
        'uptime_seconds': int(time.time() - START_TIME),
        'timestamp': datetime.utcnow().isoformat()
    })

@app.route('/api/scan', methods=['POST'])
def scan_qr():
    try:
        if 'image_file' in request.files:
            file = request.files['image_file']
            if file.filename == '' or not allowed_file(file.filename):
                return jsonify({'error': 'Invalid file'}), 400
            temp_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(temp_path)
            qr_result = extract_qr_data(temp_path)
            os.remove(temp_path)
        elif 'image_url' in request.json:
            qr_result = extract_qr_data(request.json['image_url'])
        else:
            return jsonify({'error': 'No image provided'}), 400

        if not qr_result['success']:
            return jsonify(qr_result), 400

        predictions = []
        for qr in qr_result['results']:
            if qr['type'] == 'url':
                pred = predict_url(qr['data'])
                predictions.append({'extracted_data': qr['data'], 'analysis': pred, 'qr_location': qr['rect']})
            else:
                predictions.append({'extracted_data': qr['data'], 'type': 'text', 'message': 'QR contains text, not URL'})

        return jsonify({'success': True, 'scan_summary': qr_result['message'], 'predictions': predictions, 'timestamp': datetime.now().isoformat()})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/analyze/url', methods=['POST'])
def analyze_url():
    try:
        data = request.json
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        url = data['url']
        if not validators.url(url):
            return jsonify({'error': 'Invalid URL'}), 400
        pred = predict_url(url)
        pred['analysis_time'] = datetime.now().isoformat()
        return jsonify(pred)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ----------------------------
# Run App
# ----------------------------
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)






