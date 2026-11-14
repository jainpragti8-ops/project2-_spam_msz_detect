import os
import sqlite3
import json
from datetime import datetime
from flask import Flask, render_template, request, jsonify
import joblib

from url_analyzer import analyze_url
from file_analyzer import process_file_content

app = Flask(__name__)
# Max file upload size: 16 MB
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Vercel serverless environment compatibility (filesystem is read-only except /tmp)
IS_VERCEL = bool(os.environ.get('VERCEL') or os.environ.get('AWS_LAMBDA_FUNCTION_NAME'))
if IS_VERCEL:
    DB_PATH = '/tmp/database.db'
else:
    DB_PATH = os.path.join(BASE_DIR, 'database.db')

MODEL_PATH = os.path.join(BASE_DIR, 'model.pkl')
VEC_PATH = os.path.join(BASE_DIR, 'vectorizer.pkl')
METRICS_PATH = os.path.join(BASE_DIR, 'metrics.json')

# Load Model and Vectorizer
model = None
vectorizer = None

def load_ml_assets():
    global model, vectorizer
    if os.path.exists(MODEL_PATH) and os.path.exists(VEC_PATH):
        try:
            model = joblib.load(MODEL_PATH)
            vectorizer = joblib.load(VEC_PATH)
            print("[INFO] Model and Vectorizer loaded successfully.")
            return True
        except Exception as e:
            print(f"[ERROR] Failed to load model files: {e}")
            model = None
            vectorizer = None
            return False
    else:
        print("[WARNING] Model or vectorizer file missing. Run train_model.py to generate them.")
        model = None
        vectorizer = None
        return False

load_ml_assets()

# Database helper functions with automatic column migration
def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT NOT NULL,
            result TEXT NOT NULL,
            confidence REAL NOT NULL,
            scanned_at TEXT NOT NULL,
            scan_type TEXT DEFAULT 'message'
        )
    ''')
    # Column migration check
    cursor = conn.execute("PRAGMA table_info(scans)")
    columns = [row[1] for row in cursor.fetchall()]
    if 'scan_type' not in columns:
        conn.execute("ALTER TABLE scans ADD COLUMN scan_type TEXT DEFAULT 'message'")
    conn.commit()
    return conn

get_db_connection().close()

# ----------------- Navigation Routes -----------------

@app.route('/')
def index():
    return render_template('index.html')

# 1. Message Spam Detection
@app.route('/detect')
@app.route('/detect-message')
def detect():
    model_ready = (model is not None and vectorizer is not None)
    return render_template('detect.html', model_ready=model_ready)

# 2. Link / URL Phishing Detection
@app.route('/detect-link')
def detect_link():
    return render_template('detect_link.html')

# 3. File / Document Batch Detection
@app.route('/detect-file')
def detect_file():
    model_ready = (model is not None and vectorizer is not None)
    return render_template('detect_file.html', model_ready=model_ready)

# ----------------- API Prediction Endpoints -----------------

@app.route('/predict', methods=['POST'])
def predict():
    global model, vectorizer
    if model is None or vectorizer is None:
        if not load_ml_assets():
            return jsonify({
                "error": "The AI model has not been trained yet. Please run 'python train_model.py' to generate model artifacts."
            }), 503

    message = ""
    if request.is_json:
        data = request.get_json(silent=True) or {}
        message = data.get('message', '')
    elif request.form:
        message = request.form.get('message', '')
    else:
        try:
            raw_data = json.loads(request.get_data(as_text=True) or '{}')
            message = raw_data.get('message', '')
        except Exception:
            message = ""

    if not message or not str(message).strip():
        return jsonify({"error": "Message input cannot be empty or whitespace only."}), 400

    message_clean = str(message).strip()
    if len(message_clean) > 1000:
        return jsonify({"error": "Message exceeds the maximum allowed limit of 1000 characters."}), 400

    processed_text = message_clean.lower()

    try:
        vec_features = vectorizer.transform([processed_text])
        prediction = model.predict(vec_features)[0]
        probabilities = model.predict_proba(vec_features)[0]

        is_spam = bool(prediction == 1)
        label = "Spam" if is_spam else "Not Spam"
        confidence = round(float(probabilities[prediction]) * 100, 2)

        scanned_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scans (message, result, confidence, scanned_at, scan_type) VALUES (?, ?, ?, ?, ?)",
            (message_clean, label, confidence, scanned_at, 'message')
        )
        conn.commit()
        record_id = cursor.lastrowid
        conn.close()

        return jsonify({
            "id": record_id,
            "label": label,
            "is_spam": is_spam,
            "confidence": confidence,
            "message": message_clean,
            "scanned_at": scanned_at
        })
    except Exception as e:
        return jsonify({"error": f"Prediction error: {str(e)}"}), 500

@app.route('/predict-link', methods=['POST'])
def predict_link():
    url_input = ""
    if request.is_json:
        data = request.get_json(silent=True) or {}
        url_input = data.get('url', '')
    elif request.form:
        url_input = request.form.get('url', '')
    else:
        try:
            raw_data = json.loads(request.get_data(as_text=True) or '{}')
            url_input = raw_data.get('url', '')
        except Exception:
            url_input = ""

    if not url_input or not str(url_input).strip():
        return jsonify({"error": "URL link cannot be empty."}), 400

    analysis = analyze_url(url_input.strip())
    if "error" in analysis:
        return jsonify({"error": analysis["error"]}), 400

    # Save to history
    scanned_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scans (message, result, confidence, scanned_at, scan_type) VALUES (?, ?, ?, ?, ?)",
        (analysis['url'], analysis['verdict'], analysis['confidence'], scanned_at, 'link')
    )
    conn.commit()
    record_id = cursor.lastrowid
    conn.close()

    analysis['id'] = record_id
    analysis['scanned_at'] = scanned_at
    return jsonify(analysis)

@app.route('/predict-file', methods=['POST'])
def predict_file():
    global model, vectorizer
    if model is None or vectorizer is None:
        if not load_ml_assets():
            return jsonify({
                "error": "The AI model has not been trained yet. Please run 'python train_model.py' first."
            }), 503

    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded."}), 400

    file = request.files['file']
    if not file or not file.filename:
        return jsonify({"error": "No file selected."}), 400

    # Allow common text/data extensions
    allowed_exts = {'txt', 'csv', 'tsv', 'json', 'log', 'eml'}
    ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
    if ext not in allowed_exts:
        return jsonify({"error": f"Unsupported file type '.{ext}'. Supported: .txt, .csv, .tsv, .json, .log"}), 400

    try:
        report = process_file_content(file, model, vectorizer)
        if "error" in report:
            return jsonify({"error": report["error"]}), 400

        # Save batch file summary in scans history
        summary_label = f"{report['threat_level']} ({report['spam_count']} spam / {report['total_scanned']} msgs)"
        confidence = report['spam_ratio']
        scanned_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scans (message, result, confidence, scanned_at, scan_type) VALUES (?, ?, ?, ?, ?)",
            (f"File Scan: {report['filename']}", summary_label, confidence, scanned_at, 'file')
        )
        conn.commit()
        record_id = cursor.lastrowid
        conn.close()

        report['id'] = record_id
        report['scanned_at'] = scanned_at
        return jsonify(report)

    except Exception as e:
        return jsonify({"error": f"Error scanning file: {str(e)}"}), 500

# ----------------- Dashboard, History & About -----------------

@app.route('/dashboard')
def dashboard():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM scans")
    total_scans = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE result LIKE '%Spam%' OR result LIKE '%Phishing%' OR result LIKE '%High Threat%'")
    spam_scans = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE result LIKE '%Not Spam%' OR result LIKE '%Safe%' OR result LIKE '%Clean%'")
    ham_scans = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE scan_type = 'message'")
    msg_scans = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE scan_type = 'link'")
    link_scans = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE scan_type = 'file'")
    file_scans = cursor.fetchone()[0]

    cursor.execute("SELECT id, message, result, confidence, scanned_at, scan_type FROM scans ORDER BY id DESC LIMIT 10")
    recent_scans = cursor.fetchall()

    conn.close()

    spam_rate = round((spam_scans / total_scans * 100), 1) if total_scans > 0 else 0

    return render_template(
        'dashboard.html',
        total_scans=total_scans,
        spam_scans=spam_scans,
        ham_scans=ham_scans,
        spam_rate=spam_rate,
        msg_scans=msg_scans,
        link_scans=link_scans,
        file_scans=file_scans,
        recent_scans=recent_scans
    )

@app.route('/history')
def history():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, message, result, confidence, scanned_at, scan_type FROM scans ORDER BY id DESC")
    all_scans = cursor.fetchall()
    conn.close()
    return render_template('history.html', scans=all_scans)

@app.route('/about')
def about():
    metrics = None
    if os.path.exists(METRICS_PATH):
        try:
            with open(METRICS_PATH, 'r', encoding='utf-8') as f:
                metrics = json.load(f)
        except Exception:
            metrics = None

    return render_template('about.html', metrics=metrics)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
