# ==============================================================================
# AI-Based Spam & Threat Detection System - Complete Google Colab Code
# Course: BCA (Artificial Intelligence & Machine Learning)
# ==============================================================================

# ------------------------------------------------------------------------------
# STEP 1: INSTALL & IMPORT DEPENDENCIES
# ------------------------------------------------------------------------------
import os
import re
import json
import urllib.request
from datetime import datetime
from urllib.parse import urlparse

import numpy as np
import pandas as pd
import joblib

try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    HAS_PLT = True
except ImportError:
    HAS_PLT = False

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_curve, auc
)

print("[INFO] Libraries loaded successfully.")

# ------------------------------------------------------------------------------
# STEP 2: DOWNLOAD & LOAD UCI SMS DATASET
# ------------------------------------------------------------------------------
DATASET_URL = "https://raw.githubusercontent.com/justmarkham/pycon-2016-tutorial/master/data/sms.tsv"
DATASET_FILE = "SMSSpamCollection.tsv"

# Look for existing local dataset or download in Colab
local_candidates = [
    DATASET_FILE,
    os.path.join(os.path.dirname(__file__), "spam-detection-system", "dataset", "SMSSpamCollection"),
    "dataset/SMSSpamCollection",
    "SMSSpamCollection"
]
found_file = None
for cand in local_candidates:
    if os.path.exists(cand):
        found_file = cand
        break

if not found_file:
    print(f"[*] Downloading dataset from {DATASET_URL}...")
    try:
        urllib.request.urlretrieve(DATASET_URL, DATASET_FILE)
        found_file = DATASET_FILE
        print("[*] Download complete!")
    except Exception as e:
        print(f"[!] Download failed: {e}")

df = pd.read_csv(found_file, sep='\t', names=['label', 'message'], encoding='utf-8')
df = df.dropna(subset=['label', 'message'])
df['label'] = df['label'].astype(str).str.strip().str.lower()
df['message'] = df['message'].astype(str).str.strip()
df = df[df['label'].isin(['ham', 'spam'])]

df['target'] = df['label'].map({'ham': 0, 'spam': 1})
df['char_length'] = df['message'].apply(len)

total_records = len(df)
ham_count = (df['label'] == 'ham').sum()
spam_count = (df['label'] == 'spam').sum()

print(f"[*] Dataset summary: {total_records} rows (Ham: {ham_count}, Spam: {spam_count})")

# ------------------------------------------------------------------------------
# STEP 3: TRAIN / TEST SPLIT (80/20 STRATIFIED)
# ------------------------------------------------------------------------------
X = df['message']
y = df['target']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)

print(f"[*] Training samples: {len(X_train)} | Testing samples: {len(X_test)}")

# ------------------------------------------------------------------------------
# STEP 4: TF-IDF VECTORIZATION & LOGISTIC REGRESSION TRAINING
# ------------------------------------------------------------------------------
vectorizer = TfidfVectorizer(
    lowercase=True,
    stop_words='english',
    max_features=5000,
    ngram_range=(1, 2)
)

# Fit vectorizer strictly on training data
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

# Train Classifier
model = LogisticRegression(max_iter=1000, random_state=42)
model.fit(X_train_vec, y_train)
print("[*] Model trained successfully!")

# ------------------------------------------------------------------------------
# STEP 5: EVALUATION ON HELD-OUT TEST SET
# ------------------------------------------------------------------------------
y_pred = model.predict(X_test_vec)
y_prob = model.predict_proba(X_test_vec)[:, 1]

acc = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred, pos_label=1)
rec = recall_score(y_test, y_pred, pos_label=1)
f1 = f1_score(y_test, y_pred, pos_label=1)

print("\n" + "=" * 55)
print("             MODEL EVALUATION METRICS")
print("=" * 55)
print(f"  Accuracy:         {acc * 100:.2f}%")
print(f"  Precision (Spam): {prec * 100:.2f}%")
print(f"  Recall (Spam):    {rec * 100:.2f}%")
print(f"  F1-Score (Spam):  {f1 * 100:.2f}%")
print("=" * 55 + "\n")

print("Classification Report:")
print(classification_report(y_test, y_pred, target_names=['Ham', 'Spam']))

# Save artifacts
joblib.dump(model, 'model.pkl')
joblib.dump(vectorizer, 'vectorizer.pkl')
with open('metrics.json', 'w') as f:
    json.dump({
        "accuracy": round(acc * 100, 2),
        "precision": round(prec * 100, 2),
        "recall": round(rec * 100, 2),
        "f1_score": round(f1 * 100, 2),
        "total_samples": int(total_records),
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "trained_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }, f, indent=4)

print("[*] Artifacts saved: 'model.pkl', 'vectorizer.pkl', 'metrics.json'")

# ------------------------------------------------------------------------------
# STEP 6: MODULE 2 - LINK & PHISHING URL DETECTION ENGINE
# ------------------------------------------------------------------------------
SUSPICIOUS_TLDS = {'xyz', 'top', 'club', 'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'click', 'loan', 'fit', 'racing', 'download'}
URL_SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'cutt.ly', 'rebrand.ly'}
PHISHING_KEYWORDS = ['login', 'signin', 'verify', 'account', 'update', 'banking', 'secure', 'wallet', 'password', 'claim', 'prize', 'reward', 'urgent', 'suspend']
TYPOSQUATTING_PATTERNS = [r'paypa[l1i]', r'g[o0]{2}gle', r'micr[o0]s[o0]ft', r'amaz[o0]n', r'netfl[i1]x']

def analyze_url(url_string):
    url = (url_string or "").strip()
    if not url:
        return {"error": "URL cannot be empty"}
    
    url_to_parse = url if re.match(r'^[a-zA-Z]+://', url) else 'http://' + url
    parsed = urlparse(url_to_parse)
    netloc = parsed.netloc.lower()
    full_url = url.lower()
    
    score = 0
    indicators = []
    
    if parsed.scheme == 'http':
        score += 15
        indicators.append("Non-secure HTTP protocol used.")
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}(:\d+)?$', netloc):
        score += 40
        indicators.append("Direct IP address used as hostname.")
    
    host_clean = netloc.split(':')[0]
    if host_clean in URL_SHORTENERS:
        score += 25
        indicators.append(f"Masked URL shortener '{host_clean}' detected.")
    
    tld = host_clean.split('.')[-1] if '.' in host_clean else ''
    if tld in SUSPICIOUS_TLDS:
        score += 30
        indicators.append(f"High-risk TLD '.{tld}' detected.")
        
    if host_clean.count('.') > 3:
        score += 20
        indicators.append("Excessive subdomain depth detected.")
    if '@' in url_to_parse:
        score += 35
        indicators.append("Contains '@' symbol (URL obfuscation trick).")
    if len(url) > 75:
        score += 15
        indicators.append(f"Abnormally long URL length ({len(url)} chars).")
        
    matched_kw = [kw for kw in PHISHING_KEYWORDS if kw in full_url]
    if matched_kw:
        score += min(30, len(matched_kw) * 15)
        indicators.append(f"Deceptive lure keywords: {', '.join(matched_kw[:3])}")
        
    for pattern in TYPOSQUATTING_PATTERNS:
        if re.search(pattern, host_clean) and not re.search(r'^(www\.)?(google\.com|paypal\.com|microsoft\.com|amazon\.com|netflix\.com)$', host_clean):
            score += 35
            indicators.append("Suspected brand impersonation / typosquatting.")
            break
            
    risk_score = min(99, max(5, score))
    risk_level = "High Risk Phishing" if risk_score >= 55 else ("Suspicious Link" if risk_score >= 30 else "Safe / Legitimate Link")
    
    return {
        "url": url,
        "hostname": host_clean,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "is_malicious": risk_score >= 30,
        "indicators": indicators or ["No suspicious anomalies detected"]
    }

# ------------------------------------------------------------------------------
# STEP 7: MODULE 3 - BATCH MESSAGE & FILE SCANNER
# ------------------------------------------------------------------------------
def process_batch_messages(messages_list):
    valid_msgs = [str(m).strip() for m in messages_list if len(str(m).strip()) >= 3]
    if not valid_msgs:
        return {"error": "No valid messages provided."}
    
    vecs = vectorizer.transform([m.lower() for m in valid_msgs])
    preds = model.predict(vecs)
    probs = model.predict_proba(vecs)
    
    results = []
    spam_count = 0
    for i, msg in enumerate(valid_msgs):
        p = preds[i]
        is_spam = bool(p == 1)
        conf = round(float(probs[i][p]) * 100, 2)
        if is_spam:
            spam_count += 1
        results.append({
            "index": i + 1,
            "message": msg,
            "verdict": "Spam" if is_spam else "Not Spam",
            "confidence": conf
        })
        
    total = len(valid_msgs)
    spam_ratio = round((spam_count / total * 100), 1)
    
    return {
        "total_scanned": total,
        "spam_count": spam_count,
        "ham_count": total - spam_count,
        "spam_ratio": spam_ratio,
        "threat_level": "High Threat" if spam_ratio >= 40 else ("Moderate Threat" if spam_ratio > 0 else "Clean Document"),
        "results": results
    }

# ------------------------------------------------------------------------------
# STEP 8: PREDICTION HELPER FUNCTION FOR USER TESTING
# ------------------------------------------------------------------------------
def predict_message(message_text):
    clean = (message_text or "").strip()
    if not clean:
        return {"error": "Message cannot be empty"}
    if len(clean) > 1000:
        return {"error": "Message exceeds 1000 character limit"}
        
    vec = vectorizer.transform([clean.lower()])
    pred = model.predict(vec)[0]
    prob = model.predict_proba(vec)[0]
    
    label = "Spam" if pred == 1 else "Not Spam"
    confidence = round(float(prob[pred]) * 100, 2)
    
    print(f"\n{'='*55}")
    print(f"Input Text:   '{clean}'")
    print(f"Verdict:      {label.upper()}")
    print(f"Confidence:   {confidence}%")
    print(f"{'='*55}")
    return {"label": label, "confidence": confidence}

# ------------------------------------------------------------------------------
# STEP 9: SAMPLE TEST DEMONSTRATIONS
# ------------------------------------------------------------------------------
if __name__ == '__main__':
    print("\n--- SAMPLE 1: TEST CASE TC-1 (SPAM) ---")
    predict_message("Congratulations! You won a free prize. Call now to claim.")

    print("\n--- SAMPLE 2: TEST CASE TC-2 (HAM) ---")
    predict_message("Hey, are we meeting at 5 pm today?")

    print("\n--- SAMPLE 3: PHISHING URL INSPECTION ---")
    url_res = analyze_url("http://account-verify-login-paypal.xyz/auth?claim=1")
    print(f"Target:   {url_res['url']}")
    print(f"Verdict:  {url_res['risk_level']} ({url_res['risk_score']}% threat risk)")
    print(f"Findings: {url_res['indicators']}")

    print("\n--- SAMPLE 4: BATCH FILE / DOCUMENT SCANNER ---")
    sample_batch = [
        "URGENT! You have won a £1,000 cash prize. Call 09061701461 to claim now!",
        "Can you please send me the notes from today's lecture?",
        "Free entry in 2 a weekly competition to win tickets! Text WIN to 87121",
        "See you at home for dinner tonight."
    ]
    batch_res = process_batch_messages(sample_batch)
    print(f"Scanned {batch_res['total_scanned']} messages -> Threat Level: {batch_res['threat_level']} ({batch_res['spam_ratio']}% spam)")
    for r in batch_res['results']:
        print(f"  [{r['verdict']}] ({r['confidence']}%) - {r['message'][:50]}...")
