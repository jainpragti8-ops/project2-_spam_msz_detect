# ==============================================================================
# AI-Based Spam & Threat Detection System (Short Code for Google Colab)
# BCA AI & ML Project | Compact Single-File Pipeline
# ==============================================================================

import re
import urllib.request
from urllib.parse import urlparse
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report

# 1. Download & Load UCI SMS Dataset
DATA_URL = "https://raw.githubusercontent.com/justmarkham/pycon-2016-tutorial/master/data/sms.tsv"
try:
    df = pd.read_csv(DATA_URL, sep='\t', names=['label', 'msg']).dropna()
except Exception:
    import os
    local_path = os.path.join(os.path.dirname(__file__), "spam-detection-system", "dataset", "SMSSpamCollection")
    df = pd.read_csv(local_path, sep='\t', names=['label', 'msg']).dropna()

df['target'] = df['label'].map({'ham': 0, 'spam': 1})

# 2. 80/20 Stratified Split
X_train, X_test, y_train, y_test = train_test_split(
    df['msg'], df['target'], test_size=0.20, random_state=42, stratify=df['target']
)

# 3. TF-IDF Vectorization & Logistic Regression Training
vec = TfidfVectorizer(stop_words='english', max_features=5000, ngram_range=(1, 2))
X_train_vec = vec.fit_transform(X_train)
model = LogisticRegression(max_iter=1000, random_state=42).fit(X_train_vec, y_train)

# 4. Evaluation
acc = accuracy_score(y_test, model.predict(vec.transform(X_test)))
print(f"[*] Model Trained Successfully! Test Accuracy: {acc * 100:.2f}%\n")

# 5. Universal Threat Analyzer (Handles Text Messages & URLs)
def check_threat(input_text):
    text = str(input_text).strip()
    # Check if URL / Link
    if re.match(r'^(https?://|www\.)', text) or any(tld in text for tld in ['.xyz', '.tk', '.top', '.click', '.club', '.com', '.org']):
        risk = 0
        signals = []
        host = urlparse(text if '://' in text else 'http://' + text).netloc.lower()
        if any(t in host for t in ['.xyz', '.top', '.tk', '.click', '.club', '.work']):
            risk += 35; signals.append("High-risk TLD")
        if any(s in host for s in ['bit.ly', 'tinyurl', 't.co', 'cutt.ly']):
            risk += 30; signals.append("Masked URL shortener")
        if any(k in text.lower() for k in ['login', 'verify', 'account', 'banking', 'wallet', 'claim', 'prize', 'urgent']):
            risk += 30; signals.append("Phishing lure keyword")
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}', host):
            risk += 40; signals.append("Direct IP address host")
        if not text.startswith('https://'):
            risk += 15; signals.append("Non-secure HTTP")
        risk_score = min(99, max(5, risk))
        verdict = "PHISHING / MALICIOUS LINK" if risk_score >= 40 else "SAFE LINK"
        print(f"Target URL: {text}\nVerdict:    {verdict} ({risk_score}% Threat Risk)\nSignals:    {signals or ['Safe domain pattern']}\n" + "-" * 60)
        return {"type": "url", "verdict": verdict, "score": risk_score}
    else:
        # Message Spam Classification
        v = vec.transform([text.lower()])
        pred = model.predict(v)[0]
        conf = model.predict_proba(v)[0][pred] * 100
        verdict = "SPAM" if pred == 1 else "NOT SPAM (HAM)"
        print(f"Message:    '{text}'\nVerdict:    {verdict} ({conf:.2f}% Confidence)\n" + "-" * 60)
        return {"type": "message", "verdict": verdict, "confidence": conf}

# 6. Sample Demonstrations (Test Cases TC-1, TC-2, URL)
print("-" * 60)
check_threat("Congratulations! You won a free prize. Call now to claim.")
check_threat("Hey, are we meeting at 5 pm today?")
check_threat("http://account-verify-login-paypal.xyz/auth?claim=1")
check_threat("https://www.google.com")
print("-" * 60)

# 7. Interactive Input (Type your own message or link in Colab)
user_query = input("Enter an SMS message or Website URL to check (or press Enter to skip): ")
if user_query.strip():
    check_threat(user_query)
