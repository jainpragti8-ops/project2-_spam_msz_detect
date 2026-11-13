import os
import io
import json
import sqlite3
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from app import app, DB_PATH

def test_features():
    print("=" * 70)
    print("  TESTING NEW FEATURES: MESSAGE, LINK, AND FILE DETECTION")
    print("=" * 70)

    client = app.test_client()

    # 1. Test Link Detection UI & Endpoint
    print("\n[1] Testing Link Detection...")
    res_link_page = client.get('/detect-link')
    assert res_link_page.status_code == 200, f"Expected 200 for /detect-link, got {res_link_page.status_code}"
    print("  -> GET /detect-link: OK (200)")

    # Malicious URL
    malicious_url = "http://verify-account-security-paypal.xyz/login?claim=prize"
    res_malicious = client.post('/predict-link', data=json.dumps({"url": malicious_url}), content_type='application/json')
    assert res_malicious.status_code == 200, f"Expected 200, got {res_malicious.status_code}"
    data_mal = res_malicious.get_json()
    assert data_mal['is_malicious'] is True, "Expected URL to be flagged as malicious"
    assert data_mal['risk_level'] == 'High Risk', f"Expected High Risk, got {data_mal['risk_level']}"
    print(f"  -> POST /predict-link (Phishing): OK ({data_mal['verdict']} - {data_mal['risk_score']}% risk)")

    # Safe URL
    safe_url = "https://www.wikipedia.org/wiki/Machine_learning"
    res_safe = client.post('/predict-link', data=json.dumps({"url": safe_url}), content_type='application/json')
    assert res_safe.status_code == 200, f"Expected 200, got {res_safe.status_code}"
    data_safe = res_safe.get_json()
    assert data_safe['is_malicious'] is False, "Expected URL to be safe"
    print(f"  -> POST /predict-link (Safe): OK ({data_safe['verdict']} - {data_safe['risk_score']}% risk)")

    # Empty URL validation
    res_empty_link = client.post('/predict-link', data=json.dumps({"url": "  "}), content_type='application/json')
    assert res_empty_link.status_code == 400, f"Expected 400 for empty URL, got {res_empty_link.status_code}"
    print("  -> POST /predict-link (Validation empty): OK (Rejected with 400)")

    # 2. Test File Detection UI & Endpoint
    print("\n[2] Testing File Detection...")
    res_file_page = client.get('/detect-file')
    assert res_file_page.status_code == 200, f"Expected 200 for /detect-file, got {res_file_page.status_code}"
    print("  -> GET /detect-file: OK (200)")

    # Create dummy text file with both spam and ham messages
    file_content = """URGENT! You have won a 1 week FREE vacation. Text WIN to 80085 now!
Hey, are we having lunch today at 1pm?
Congratulations! Your account was credited $5,000 cash. Call 080012345 to claim!
Can you please send me the project report by evening? Thanks."""

    data = {
        'file': (io.BytesIO(file_content.encode('utf-8')), 'test_messages.txt')
    }
    res_file = client.post('/predict-file', data=data, content_type='multipart/form-data')
    assert res_file.status_code == 200, f"Expected 200 for /predict-file, got {res_file.status_code}"
    report = res_file.get_json()
    assert report['total_scanned'] == 4, f"Expected 4 scanned messages, got {report['total_scanned']}"
    assert report['spam_count'] == 2, f"Expected 2 spam messages, got {report['spam_count']}"
    assert report['ham_count'] == 2, f"Expected 2 ham messages, got {report['ham_count']}"
    print(f"  -> POST /predict-file: OK (Scanned {report['total_scanned']} messages | Spam: {report['spam_count']}, Ham: {report['ham_count']})")

    # 3. Test Dashboard and History
    print("\n[3] Testing Dashboard and History with all scan types...")
    res_dash = client.get('/dashboard')
    assert res_dash.status_code == 200
    html_dash = res_dash.get_data(as_text=True)
    assert "Detector Breakdown" in html_dash
    print("  -> GET /dashboard: OK (Displays multi-engine breakdown)")

    res_hist = client.get('/history')
    assert res_hist.status_code == 200
    html_hist = res_hist.get_data(as_text=True)
    assert "Link" in html_hist
    assert "File" in html_hist
    print("  -> GET /history: OK (Displays Link and File badges)")

    print("\n" + "=" * 70)
    print("  ALL NEW DETECTOR FEATURES TESTED AND WORKING PERFECTLY!")
    print("=" * 70)

if __name__ == '__main__':
    test_features()

