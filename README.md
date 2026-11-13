# AI-Based Spam & Threat Detection System

A multi-vector cybersecurity web application built with Python, Flask, Scikit-Learn, and SQLite to detect spam messages, malicious links, and infected text documents.

---

## 🚀 Features

### 1. 💬 Spam Message Detection (`/detect`)
- **Machine Learning Classification Engine:** Evaluates text messages using Scikit-Learn Logistic Regression and TF-IDF n-gram vectorization.
- **Real-Time Confidence Scoring:** Outputs calibrated prediction probability percentages.
- **Interactive Controls:** Quick testing samples, character counter, and instant clearing.

### 2. 🔗 Link & URL Scanner (`/detect-link`)
- **Anti-Phishing Inspection Engine:** Analyzes website URLs against 11+ structural security heuristics.
- **Checks Performed:** Suspicious TLDs (`.xyz`, `.top`, `.tk`), masked URL shorteners (`bit.ly`, `tinyurl`), direct IP hostnames, deceptive keyword lures (`login`, `verify`, `banking`, `wallet`), brand typosquatting, and non-HTTPS protocol warnings.
- **Risk Assessment:** Outputs threat risk scores and itemized security findings.

### 3. 📁 File & Batch Document Scanner (`/detect-file`)
- **Bulk Dataset & Document Ingestion:** Supports `.csv`, `.txt`, `.tsv`, `.json`, and `.log` files (up to 16 MB).
- **Automated Text Extraction:** Parses text rows or lines and runs high-throughput batch classification.
- **Threat Analytics & Export:** Displays overall file threat level, spam vs. clean counts, interactive results table, and single-click CSV export.

### 4. 📊 Dashboard & Audit History (`/dashboard` & `/history`)
- **Multi-Vector Analytics:** Visualizes total scans, threat ratios, and breakdown across Messages, Links, and Files.
- **Detailed History Log:** Full database audit trail stored locally in SQLite (`database.db`) with expandable inspect modals.

---

## 📁 Project Structure
```
spam-detection-system/
├── app.py                      # Flask backend & REST routing
├── url_analyzer.py             # URL security & phishing heuristic engine
├── file_analyzer.py            # Batch document parser & bulk ML scanner
├── train_model.py              # ML pipeline: TF-IDF + Logistic Regression
├── model.pkl                   # Trained model artifact
├── vectorizer.pkl              # Fitted TF-IDF vectorizer artifact
├── metrics.json                # Test set evaluation results
├── database.db                 # SQLite database for audit logs
├── requirements.txt            # Python dependencies
├── README.md                   # Documentation
├── dataset/
│   └── SMSSpamCollection      # UCI Machine Learning Repository dataset
├── templates/                  # Jinja2 HTML templates
│   ├── base.html              # Shared layout & navigation dropdown
│   ├── index.html             # Multi-vector landing page
│   ├── detect.html            # Spam message detector
│   ├── detect_link.html       # Link & phishing URL scanner
│   ├── detect_file.html       # Batch file & dataset scanner
│   ├── dashboard.html         # Threat intelligence dashboard
│   ├── history.html           # Full audit trail & modal inspector
│   └── about.html             # Methodology & verified metrics
└── static/
    ├── css/style.css          # Cyber dark theme (#0a1128, cyan, royal blue)
    └── js/script.js           # Client AJAX, drag-and-drop & CSV export
```

---

## 🛠️ Quickstart

```powershell
# 1. Activate Virtual Environment
.\.venv\Scripts\Activate.ps1

# 2. Start the Server
python app.py
```
Open your browser and navigate to:
**`http://127.0.0.1:5000`**
