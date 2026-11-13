import os
import sys
import json
from datetime import datetime
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
import joblib

def get_dataset_path():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(base_dir, 'dataset', 'SMSSpamCollection'),
        os.path.join(base_dir, 'dataset', 'sms.tsv'),
        os.path.join(base_dir, 'dataset', 'spam.csv'),
        os.path.join(base_dir, 'SMSSpamCollection')
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None

def train():
    print("=" * 60)
    print("  AI-Based Spam Detection System - Model Training")
    print("=" * 60)

    dataset_path = get_dataset_path()
    if not dataset_path:
        print("[ERROR] Dataset not found! Please ensure 'SMSSpamCollection' or 'sms.tsv' is in the 'dataset/' folder.")
        sys.exit(1)

    print(f"[*] Loading dataset from: {dataset_path}")
    
    # Try reading as tab-separated without headers
    try:
        df = pd.read_csv(dataset_path, sep='\t', names=['label', 'message'], encoding='utf-8', quoting=3)
    except Exception as e:
        print(f"[!] UTF-8 read failed ({e}), trying latin-1...")
        df = pd.read_csv(dataset_path, sep='\t', names=['label', 'message'], encoding='latin-1', quoting=3)

    # Validate dataset structure
    if 'label' not in df.columns or 'message' not in df.columns:
        # Fallback if comma separated
        df = pd.read_csv(dataset_path, encoding='latin-1')
        if 'v1' in df.columns and 'v2' in df.columns:
            df = df[['v1', 'v2']].rename(columns={'v1': 'label', 'v2': 'message'})

    df = df.dropna(subset=['label', 'message'])
    df['label'] = df['label'].astype(str).str.strip().str.lower()
    df['message'] = df['message'].astype(str).str.strip()

    # Filter to only valid ham / spam labels
    df = df[df['label'].isin(['ham', 'spam'])]
    
    total_samples = len(df)
    spam_count = (df['label'] == 'spam').sum()
    ham_count = (df['label'] == 'ham').sum()

    print(f"[*] Total valid records: {total_samples} (Ham: {ham_count}, Spam: {spam_count})")

    # Map labels: ham -> 0, spam -> 1
    y = df['label'].map({'ham': 0, 'spam': 1})
    X = df['message']

    # Stratified 80/20 train/test split
    print("[*] Splitting dataset: 80% Train, 20% Test (Stratified, random_state=42)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # Feature extraction with TF-IDF Vectorizer
    print("[*] Fitting TF-IDF Vectorizer on training data...")
    vectorizer = TfidfVectorizer(
        lowercase=True,
        stop_words='english',
        max_features=5000,
        ngram_range=(1, 2)
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    # Train Logistic Regression model
    print("[*] Training Logistic Regression classifier...")
    model = LogisticRegression(max_iter=1000, random_state=42)
    model.fit(X_train_vec, y_train)

    # Evaluate on held-out test set
    print("[*] Evaluating model on unseen test set...")
    y_pred = model.predict(X_test_vec)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, pos_label=1, zero_division=0)
    rec = recall_score(y_test, y_pred, pos_label=1, zero_division=0)
    f1 = f1_score(y_test, y_pred, pos_label=1, zero_division=0)

    print("\n" + "-" * 50)
    print("  MODEL EVALUATION RESULTS (TEST SET)")
    print("-" * 50)
    print(f"  Accuracy:         {acc * 100:.2f}%")
    print(f"  Precision (Spam): {prec * 100:.2f}%")
    print(f"  Recall (Spam):    {rec * 100:.2f}%")
    print(f"  F1-Score (Spam):  {f1 * 100:.2f}%")
    print("-" * 50 + "\n")

    print(classification_report(y_test, y_pred, target_names=['Ham', 'Spam']))

    # Save artifacts
    base_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(base_dir, 'model.pkl')
    vec_path = os.path.join(base_dir, 'vectorizer.pkl')
    metrics_path = os.path.join(base_dir, 'metrics.json')

    print("[*] Saving model to 'model.pkl'...")
    joblib.dump(model, model_path)

    print("[*] Saving vectorizer to 'vectorizer.pkl'...")
    joblib.dump(vectorizer, vec_path)

    metrics_data = {
        "accuracy": round(acc * 100, 2),
        "precision": round(prec * 100, 2),
        "recall": round(rec * 100, 2),
        "f1_score": round(f1 * 100, 2),
        "total_samples": int(total_samples),
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "trained_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    with open(metrics_path, 'w', encoding='utf-8') as f:
        json.dump(metrics_data, f, indent=4)
    print(f"[*] Evaluation metrics saved to '{metrics_path}'")

    print("\n[SUCCESS] Model training complete! Artifacts generated successfully.")

if __name__ == '__main__':
    train()

