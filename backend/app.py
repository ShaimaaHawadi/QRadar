"""
QR Code Malicious URL Detection System
Deployed on Render - Backend API
"""
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import numpy as np
import tensorflow as tf
from PIL import Image
import cv2
from io import BytesIO
import requests
from urllib.parse import urlparse
import validators
import os
from datetime import datetime
import json

# Initialize Flask app
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Configuration
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = 'temp_uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp'}

# Create upload folder if not exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Load your trained model
MODEL_PATH = 'model/final_url_classifier.h5'

def load_model():
    """Load the pre-trained TensorFlow/Keras model"""
    try:
        model = tf.keras.models.load_model(MODEL_PATH)
        print(" Model loaded successfully")
        return model
    except Exception as e:
        print(f" Error loading model: {e}")
        return None

# Global model variable
model = load_model()

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_qr_data(image_path_or_url):
    """
    Extract data from QR code image
    
    Args:
        image_path_or_url: Path to image file or URL
    
    Returns:
        dict: Extracted data and status
    """
    try:
        # Handle URL or file path
        if image_path_or_url.startswith(('http://', 'https://')):
            response = requests.get(image_path_or_url, timeout=10)
            image_bytes = BytesIO(response.content)
            img = Image.open(image_bytes)
        else:
            img = Image.open(image_path_or_url)
        
        # Convert to OpenCV format
        img_cv = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
        
        # Decode QR code using OpenCV
        detector = cv2.QRCodeDetector()
        data, points, _ = detector.detectAndDecodeMulti(img_cv)  # لدعم أكثر من QR
        results = []

        # detectAndDecodeMulti قد يرجع None إذا لم يوجد QR
        if points is not None and data:
            for i, qr_data in enumerate(data):
                if qr_data:  # تحقق من أن البيانات ليست فارغة
                    is_url = validators.url(qr_data)
                    polygon = points[i].tolist() if points is not None else None
                    x, y, w, h = cv2.boundingRect(points[i].astype(int)) if points is not None else (0,0,0,0)

                    results.append({
                        'data': qr_data,
                        'type': 'url' if is_url else 'text',
                        'rect': {'x': x, 'y': y, 'w': w, 'h': h},
                        'polygon': polygon
                    })
            
            return {
                'success': True,
                'results': results,
                'message': f'Found {len(results)} QR code(s)'
            }
        else:
            return {
                'success': False,
                'message': 'No QR code found in image'
            }
    
    except Exception as e:
        return {
            'success': False,
            'message': f'Error processing image: {str(e)}'
        

def preprocess_url_for_model(url):
    """
    Preprocess URL for model input
    
    Args:
        url: URL string
    
    Returns:
        np.array: Preprocessed features
    """
    # Example feature extraction (customize based on your model)
    features = []
    
    # 1. URL length
    features.append(len(url))
    
    # 2. Number of special characters
    special_chars = ['@', '!', '#', '$', '%', '&', '*', '(', ')']
    features.append(sum([1 for char in url if char in special_chars]))
    
    # 3. Contains IP address
    import re
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    features.append(1 if re.search(ip_pattern, url) else 0)
    
    # 4. Number of subdomains
    parsed_url = urlparse(url)
    features.append(parsed_url.netloc.count('.') - 1)
    
    # 5. Uses HTTPS
    features.append(1 if parsed_url.scheme == 'https' else 0)
    
    # 6. URL depth (number of path segments)
    features.append(len([seg for seg in parsed_url.path.split('/') if seg]))
    
    # Normalize features (example - customize based on your training)
    features = np.array(features).reshape(1, -1)
    
    # Normalization (min-max scaling)
    # You should use the same normalization as during training
    features = features / np.array([200, 10, 1, 5, 1, 10])
    
    return features

def predict_url(url):
    """
    Predict if URL is malicious or benign
    
    Args:
        url: URL string
    
    Returns:
        dict: Prediction results
    """
    try:
        if model is None:
            return {
                'success': False,
                'error': 'Model not loaded'
            }
        
        # Preprocess URL
        features = preprocess_url_for_model(url)
        
        # Make prediction
        prediction = model.predict(features, verbose=0)
        
        # Assuming binary classification: 0 = benign, 1 = malicious
        confidence = float(prediction[0][0])
        
        # Determine class based on threshold
        threshold = 0.5
        is_malicious = confidence > threshold
        
        return {
            'success': True,
            'url': url,
            'is_malicious': bool(is_malicious),
            'confidence': confidence,
            'prediction': 'malicious' if is_malicious else 'benign',
            'risk_level': 'High' if confidence > 0.7 else 'Medium' if confidence > 0.4 else 'Low'
        }
    
    except Exception as e:
        return {
            'success': False,
            'error': f'Prediction error: {str(e)}'
        }

@app.route('/')
def home():
    """Home page with API documentation"""
    return render_template('index.html')

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'model_loaded': model is not None,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/scan', methods=['POST'])
def scan_qr():
    """
    API endpoint to scan QR code and analyze URL
    
    Expects:
    - image_url: URL of QR code image
    OR
    - image_file: Multipart form file
    
    Returns:
    - JSON with scan results and prediction
    """
    try:
        # Get data from request
        if 'image_file' in request.files:
            file = request.files['image_file']
            
            if file.filename == '':
                return jsonify({'error': 'No file selected'}), 400
            
            if not allowed_file(file.filename):
                return jsonify({'error': 'File type not allowed'}), 400
            
            # Save temporary file
            temp_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(temp_path)
            
            # Extract QR data
            qr_result = extract_qr_data(temp_path)
            
            # Clean up
            os.remove(temp_path)
            
        elif 'image_url' in request.json:
            image_url = request.json['image_url']
            qr_result = extract_qr_data(image_url)
        
        else:
            return jsonify({'error': 'No image provided'}), 400
        
        if not qr_result['success']:
            return jsonify(qr_result), 400
        
        # Process each extracted QR code
        predictions = []
        for qr_data in qr_result['results']:
            if qr_data['type'] == 'url':
                # Analyze URL
                pred_result = predict_url(qr_data['data'])
                
                if pred_result['success']:
                    predictions.append({
                        'extracted_data': qr_data['data'],
                        'analysis': pred_result,
                        'qr_location': {
                            'rect': qr_data['rect'],
                            'polygon': qr_data['polygon']
                        }
                    })
                else:
                    predictions.append({
                        'extracted_data': qr_data['data'],
                        'error': pred_result['error'],
                        'qr_location': qr_data['rect']
                    })
            else:
                # Non-URL QR codes
                predictions.append({
                    'extracted_data': qr_data['data'],
                    'type': 'text',
                    'message': 'QR contains text, not URL'
                })
        
        return jsonify({
            'success': True,
            'scan_summary': qr_result['message'],
            'predictions': predictions,
            'timestamp': datetime.now().isoformat()
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/analyze/url', methods=['POST'])
def analyze_url():
    """
    Direct URL analysis endpoint
    
    Expects:
    - url: URL string to analyze
    """
    try:
        data = request.json
        
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        
        url = data['url']
        
        # Validate URL
        if not validators.url(url):
            return jsonify({'error': 'Invalid URL format'}), 400
        
        # Get prediction
        prediction = predict_url(url)
        
        if not prediction['success']:
            return jsonify(prediction), 500
        
        # Add metadata
        prediction['analysis_time'] = datetime.now().isoformat()
        prediction['url_length'] = len(url)
        
        return jsonify(prediction)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/model/info', methods=['GET'])
def model_info():
    """Get model information"""
    if model is None:
        return jsonify({'error': 'Model not loaded'}), 500
    
    try:
        # Get model summary
        summary = []
        model.summary(print_fn=lambda x: summary.append(x))
        
        return jsonify({
            'model_name': MODEL_PATH,
            'layers': len(model.layers),
            'input_shape': model.input_shape,
            'output_shape': model.output_shape,
            'trainable_params': model.count_params(),
            'summary': summary
        })
    
    except Exception as e:
        return jsonify({'model_loaded': True, 'error': str(e)})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))

    app.run(host='0.0.0.0', port=port, debug=False)

