import os
import sys
import json
import sqlite3
import shutil

# Ensure working directory is project root
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from app import app, DB_PATH, MODEL_PATH, VEC_PATH

def run_tests():
    print("=" * 70)
    print("  AI-BASED SPAM DETECTION SYSTEM - FULL TEST SUITE (TC-1 to TC-12)")
    print("=" * 70)

    # 1. Clean slate for testing: remove old test database if present
    if os.path.exists(DB_PATH):
        try:
            os.remove(DB_PATH)
        except Exception:
            pass

    client = app.test_client()
    passed = 0
    failed = 0

    def check(test_id, description, condition, details=""):
        nonlocal passed, failed
        if condition:
            passed += 1
            print(f" [PASS] {test_id}: {description} {details}")
        else:
            failed += 1
            print(f" [FAIL] {test_id}: {description} {details}")

    # TC-1: Spam message
    payload_tc1 = {"message": "Congratulations! You won a free prize. Call now to claim."}
    res_tc1 = client.post('/predict', data=json.dumps(payload_tc1), content_type='application/json')
    data_tc1 = res_tc1.get_json() if res_tc1.is_json else {}
    check("TC-1", "Spam Message Prediction", 
          res_tc1.status_code == 200 and data_tc1.get('label') == 'Spam',
          f"-> Got '{data_tc1.get('label')}' ({data_tc1.get('confidence')}%)")

    # TC-2: Ham message
    payload_tc2 = {"message": "Hey, are we meeting at 5 pm today?"}
    res_tc2 = client.post('/predict', data=json.dumps(payload_tc2), content_type='application/json')
    data_tc2 = res_tc2.get_json() if res_tc2.is_json else {}
    check("TC-2", "Ham Message Prediction", 
          res_tc2.status_code == 200 and data_tc2.get('label') == 'Not Spam',
          f"-> Got '{data_tc2.get('label')}' ({data_tc2.get('confidence')}%)")

    # Count records so far (should be exactly 2)
    conn = sqlite3.connect(DB_PATH)
    count_after_tc2 = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    conn.close()

    # TC-3: Empty input
    res_tc3 = client.post('/predict', data=json.dumps({"message": ""}), content_type='application/json')
    conn = sqlite3.connect(DB_PATH)
    count_after_tc3 = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    conn.close()
    check("TC-3", "Empty input validation", 
          res_tc3.status_code == 400 and count_after_tc3 == count_after_tc2,
          f"-> HTTP {res_tc3.status_code}, DB unchanged ({count_after_tc3} records)")

    # TC-4: Whitespace only
    res_tc4 = client.post('/predict', data=json.dumps({"message": "     \n\t  "}), content_type='application/json')
    conn = sqlite3.connect(DB_PATH)
    count_after_tc4 = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    conn.close()
    check("TC-4", "Whitespace-only input validation", 
          res_tc4.status_code == 400 and count_after_tc4 == count_after_tc2,
          f"-> HTTP {res_tc4.status_code}, DB unchanged ({count_after_tc4} records)")

    # TC-5: Over-length input (1,001+ characters)
    long_msg = "A" * 1005
    res_tc5 = client.post('/predict', data=json.dumps({"message": long_msg}), content_type='application/json')
    conn = sqlite3.connect(DB_PATH)
    count_after_tc5 = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    conn.close()
    check("TC-5", "Over-length input validation (1000+ chars)", 
          res_tc5.status_code == 400 and count_after_tc5 == count_after_tc2,
          f"-> HTTP {res_tc5.status_code}, Message: '{res_tc5.get_json().get('error')}'")

    # TC-6: Clear button behavior (verified in detect.html / script.js)
    with open(os.path.join(BASE_DIR, 'static', 'js', 'script.js'), 'r', encoding='utf-8') as f:
        js_code = f.read()
    check("TC-6", "Clear button resets inputs & hides results in script.js",
          "btnClear.addEventListener" in js_code and "hideResult()" in js_code and "hideError()" in js_code)

    # TC-7: History saved
    res_tc7 = client.get('/history')
    html_tc7 = res_tc7.get_data(as_text=True)
    check("TC-7", "History page lists TC-1 and TC-2 scans",
          res_tc7.status_code == 200 and "Congratulations! You won a free prize" in html_tc7 and "Hey, are we meeting at 5 pm" in html_tc7)

    # TC-8: Dashboard counts (Total = 2, Spam = 1, Ham = 1)
    res_tc8 = client.get('/dashboard')
    html_tc8 = res_tc8.get_data(as_text=True)
    conn = sqlite3.connect(DB_PATH)
    c_total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    c_spam = conn.execute("SELECT COUNT(*) FROM scans WHERE result='Spam'").fetchone()[0]
    c_ham = conn.execute("SELECT COUNT(*) FROM scans WHERE result='Not Spam'").fetchone()[0]
    conn.close()
    check("TC-8", "Dashboard metrics accurate",
          res_tc8.status_code == 200 and c_total == 2 and c_spam == 1 and c_ham == 1,
          f"-> Total: {c_total}, Spam: {c_spam}, Ham: {c_ham}")

    # TC-9: Empty database handling
    # Temporarily remove database.db
    os.remove(DB_PATH)
    res_tc9_dash = client.get('/dashboard')
    res_tc9_hist = client.get('/history')
    html_tc9_dash = res_tc9_dash.get_data(as_text=True)
    html_tc9_hist = res_tc9_hist.get_data(as_text=True)
    check("TC-9", "Empty database auto-recovery & zero states",
          res_tc9_dash.status_code == 200 and res_tc9_hist.status_code == 200 and "No scans recorded yet" in html_tc9_dash and "Audit history is empty" in html_tc9_hist)

    # TC-10: Missing model handling
    # Temporarily rename model.pkl
    backup_model = MODEL_PATH + ".bak"
    if os.path.exists(MODEL_PATH):
        shutil.move(MODEL_PATH, backup_model)
    
    # Reload app state without model
    import app as app_module
    app_module.load_ml_assets()

    res_tc10_detect = client.get('/detect')
    html_tc10_detect = res_tc10_detect.get_data(as_text=True)
    res_tc10_predict = client.post('/predict', data=json.dumps({"message": "Hello"}), content_type='application/json')

    check("TC-10", "Missing model friendly error & non-crashing UI",
          res_tc10_detect.status_code == 200 and "Model Not Found!" in html_tc10_detect and res_tc10_predict.status_code == 503,
          f"-> Detect HTTP {res_tc10_detect.status_code}, Predict HTTP {res_tc10_predict.status_code}")

    # Restore model
    if os.path.exists(backup_model):
        shutil.move(backup_model, MODEL_PATH)
    app_module.load_ml_assets()

    # TC-11: HTML injection / XSS prevention
    xss_payload = "<script>alert(1)</script>"
    res_tc11_pred = client.post('/predict', data=json.dumps({"message": xss_payload}), content_type='application/json')
    res_tc11_hist = client.get('/history')
    html_tc11 = res_tc11_hist.get_data(as_text=True)
    # Must NOT have unescaped raw tag in the HTML body
    is_safe = ("&lt;script&gt;alert(1)&lt;/script&gt;" in html_tc11 or "&#60;script&#62;" in html_tc11) and "<script>alert(1)</script>" not in html_tc11
    check("TC-11", "HTML injection safe escaping (Jinja2 auto-escape)",
          res_tc11_pred.status_code == 200 and is_safe)

    # TC-12: Responsive layout & Bootstrap integration
    with open(os.path.join(BASE_DIR, 'templates', 'base.html'), 'r', encoding='utf-8') as f:
        base_html = f.read()
    check("TC-12", "Responsive layout with Bootstrap grid & collapsible navbar",
          "navbar-toggler" in base_html and "data-bs-toggle=\"collapse\"" in base_html and "container" in base_html)

    print("-" * 70)
    print(f"  TEST SUMMARY: {passed} PASSED / {failed} FAILED (Total: {passed + failed})")
    print("=" * 70)

    if failed > 0:
        sys.exit(1)

if __name__ == '__main__':
    run_tests()

