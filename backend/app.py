"""
QR Code & URL Malicious Detection Backend
Flask + TensorFlow
Compatible with Render
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import tensorflow as tf
import numpy as np
import cv2
from PIL import Image
from io import BytesIO
import requests
import validators
import os
from datetime import datetime
from urllib.parse import urlparse

# -----------------------
# App Initialization
# -----------------------
app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = "temp"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

MODEL_PATH = "model/final_url_classifier.h5"

# -----------------------
# Load Model
# -----------------------
try:
    model = tf.keras.models.load_model(MODEL_PATH)
    print("✅ Model loaded successfully")
except Exception as e:
    print("❌ Model loading failed:", e)
    model = None


# -----------------------
# QR Code Extraction
# -----------------------
def extract_qr_data(image_path_or_url):
    try:
        # Load image
        if image_path_or_url.startswith(("http://", "https://")):
            response = requests.get(image_path_or_url, timeout=10)
            image = Image.open(BytesIO(response.content)).convert("RGB")
        else:
            image = Image.open(image_path_or_url).convert("RGB")

        img_cv = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)

        detector = cv2.QRCodeDetector()
        data_list, points, _ = detector.detectAndDecodeMulti(img_cv)

        if points is None or not data_list:
            return {"success": False, "message": "No QR code found"}

        results = []
        for i, data in enumerate(data_list):
            if not data:
                continue

            x, y, w, h = cv2.boundingRect(points[i].astype(int))
            results.append({
                "data": data,
                "is_url": validators.url(data),
                "rect": {"x": x, "y": y, "w": w, "h": h}
            })

        return {"success": True, "results": results}

    except Exception as e:
        return {"success": False, "error": str(e)}


# -----------------------
# URL Preprocessing
# -----------------------
def preprocess_url(url):
    features = []

    features.append(len(url))  # URL length
    features.append(url.count("."))  # dot count
    features.append(url.count("/"))  # slash count
    features.append(1 if "@" in url else 0)  # suspicious char
    features.append(1 if url.startswith("https") else 0)  # HTTPS

    parsed = urlparse(url)
    features.append(parsed.netloc.count("-"))  # hyphen count

    features = np.array(features, dtype=np.float32).reshape(1, -1)
    features /= np.array([200, 10, 10, 1, 1, 5])  # normalization

    return features


# -----------------------
# Prediction
# -----------------------
def predict_url(url):
    if model is None:
        return {"success": False, "error": "Model not loaded"}

    features = preprocess_url(url)
    prediction = model.predict(features, verbose=0)[0][0]

    return {
        "success": True,
        "url": url,
        "prediction": "malicious" if prediction > 0.5 else "benign",
        "confidence": float(prediction)
    }


# -----------------------
# Routes
# -----------------------
@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "QR & URL Malicious Detection API",
        "status": "running"
    })


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "model_loaded": model is not None,
        "time": datetime.now().isoformat()
    })


@app.route("/api/scan", methods=["POST"])
def scan_qr():
    try:
        # Image file
        if "image" in request.files:
            file = request.files["image"]
            path = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(path)
            qr_result = extract_qr_data(path)
            os.remove(path)

        # Image URL
        elif request.json and "image_url" in request.json:
            qr_result = extract_qr_data(request.json["image_url"])

        else:
            return jsonify({"error": "No image provided"}), 400

        if not qr_result["success"]:
            return jsonify(qr_result), 400

        results = []
        for item in qr_result["results"]:
            if item["is_url"]:
                analysis = predict_url(item["data"])
                results.append({
                    "qr_data": item["data"],
                    "analysis": analysis
                })
            else:
                results.append({
                    "qr_data": item["data"],
                    "analysis": "Not a URL"
                })

        return jsonify({
            "success": True,
            "results": results
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/analyze/url", methods=["POST"])
def analyze_url():
    data = request.json
    if not data or "url" not in data:
        return jsonify({"error": "URL required"}), 400

    url = data["url"]
    if not validators.url(url):
        return jsonify({"error": "Invalid URL"}), 400

    return jsonify(predict_url(url))


# -----------------------
# Main
# -----------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
