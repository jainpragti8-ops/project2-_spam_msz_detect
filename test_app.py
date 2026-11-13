import json
from app import app, init_db

def test_routes():
    init_db()
    client = app.test_client()

    print("[*] Testing GET / ...")
    res = client.get('/')
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    print("    -> PASS")

    print("[*] Testing GET /detect ...")
    res = client.get('/detect')
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    print("    -> PASS")

    print("[*] Testing POST /predict (Spam message) ...")
    spam_payload = {"message": "URGENT! You have won a £1000 cash prize! Text CLAIM to 87121 now to collect your reward."}
    res = client.post('/predict', data=json.dumps(spam_payload), content_type='application/json')
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    data = res.get_json()
    assert data['label'] == 'Spam', f"Expected Spam, got {data['label']}"
    print(f"    -> PASS (Verdict: {data['label']}, Confidence: {data['confidence']}%)")

    print("[*] Testing POST /predict (Ham message) ...")
    ham_payload = {"message": "Hey mate, can you bring the notes to class tomorrow? Thanks!"}
    res = client.post('/predict', data=json.dumps(ham_payload), content_type='application/json')
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    data = res.get_json()
    assert data['label'] == 'Not Spam', f"Expected Not Spam, got {data['label']}"
    print(f"    -> PASS (Verdict: {data['label']}, Confidence: {data['confidence']}%)")

    print("[*] Testing POST /predict (Validation - Empty input) ...")
    empty_payload = {"message": "   "}
    res = client.post('/predict', data=json.dumps(empty_payload), content_type='application/json')
    assert res.status_code == 400, f"Expected 400, got {res.status_code}"
    print("    -> PASS (Properly rejected with 400)")

    print("[*] Testing GET /dashboard ...")
    res = client.get('/dashboard')
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    assert b"Threat Intelligence Dashboard" in res.data
    print("    -> PASS")

    print("[*] Testing GET /history ...")
    res = client.get('/history')
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    assert b"Message Scan Audit Log" in res.data
    print("    -> PASS")

    print("[*] Testing GET /about ...")
    res = client.get('/about')
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    assert b"Verified Model Performance" in res.data
    print("    -> PASS")

    print("\n[ALL TESTS PASSED SUCCESSFULLY!]")

if __name__ == '__main__':
    test_routes()

