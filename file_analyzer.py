import io
import csv
import json
import pandas as pd

def process_file_content(file_storage, model, vectorizer, max_records=300):
    """
    Parses an uploaded file (CSV, TXT, TSV, JSON), extracts text messages,
    and runs batch ML spam classification.
    """
    filename = file_storage.filename or "uploaded_file"
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''

    raw_bytes = file_storage.read()
    if not raw_bytes:
        return {"error": "Uploaded file is empty"}

    # Attempt decode
    try:
        text_content = raw_bytes.decode('utf-8')
    except UnicodeDecodeError:
        try:
            text_content = raw_bytes.decode('latin-1')
        except Exception as e:
            return {"error": f"Failed to decode file: {str(e)}"}

    messages = []

    # 1. CSV / TSV Parsing
    if ext in ['csv', 'tsv']:
        delimiter = '\t' if ext == 'tsv' else ','
        try:
            stream = io.StringIO(text_content)
            df = pd.read_csv(stream, sep=delimiter, on_bad_lines='skip')
            
            # Find candidate text column
            target_col = None
            for candidate in ['message', 'text', 'sms', 'body', 'content', 'v2', 'msg', 'clean_text']:
                matches = [c for c in df.columns if candidate in c.lower()]
                if matches:
                    target_col = matches[0]
                    break

            if not target_col:
                # Pick the first string column with average length > 5
                for c in df.columns:
                    if df[c].dtype == object and df[c].astype(str).str.len().mean() > 5:
                        target_col = c
                        break

            if target_col:
                messages = df[target_col].dropna().astype(str).str.strip().tolist()
            else:
                # Fallback to reading first column as lines
                messages = [line.strip() for line in text_content.splitlines() if line.strip()]
        except Exception:
            messages = [line.strip() for line in text_content.splitlines() if line.strip()]

    # 2. JSON Parsing
    elif ext == 'json':
        try:
            parsed = json.loads(text_content)
            if isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, str) and item.strip():
                        messages.append(item.strip())
                    elif isinstance(item, dict):
                        for k in ['message', 'text', 'sms', 'body', 'content']:
                            if k in item and isinstance(item[k], str) and item[k].strip():
                                messages.append(item[k].strip())
                                break
        except Exception:
            messages = [line.strip() for line in text_content.splitlines() if line.strip()]

    # 3. Plain Text / Log Parsing
    else:
        messages = [line.strip() for line in text_content.splitlines() if line.strip()]

    # Deduplicate and cap records
    valid_messages = [m for m in messages if len(m) >= 3][:max_records]
    if not valid_messages:
        return {"error": "No valid readable text messages could be extracted from the uploaded file."}

    # Batch Predict using ML pipeline
    spam_count = 0
    ham_count = 0
    detailed_results = []

    vec_features = vectorizer.transform([m.lower() for m in valid_messages])
    predictions = model.predict(vec_features)
    probabilities = model.predict_proba(vec_features)

    for idx, msg in enumerate(valid_messages):
        pred = predictions[idx]
        is_spam = bool(pred == 1)
        conf = round(float(probabilities[idx][pred]) * 100, 2)

        if is_spam:
            spam_count += 1
            verdict = "Spam"
        else:
            ham_count += 1
            verdict = "Not Spam"

        detailed_results.append({
            "index": idx + 1,
            "message": msg[:200] + ("..." if len(msg) > 200 else ""),
            "full_message": msg,
            "verdict": verdict,
            "is_spam": is_spam,
            "confidence": conf
        })

    total = len(valid_messages)
    spam_ratio = round((spam_count / total * 100), 1) if total > 0 else 0

    if spam_ratio >= 40:
        threat_level = "High Threat"
        badge_class = "danger"
    elif spam_ratio > 0:
        threat_level = "Moderate Threat"
        badge_class = "warning"
    else:
        threat_level = "Clean File"
        badge_class = "success"

    return {
        "filename": filename,
        "total_scanned": total,
        "spam_count": spam_count,
        "ham_count": ham_count,
        "spam_ratio": spam_ratio,
        "threat_level": threat_level,
        "badge_class": badge_class,
        "results": detailed_results
    }

