import re
from urllib.parse import urlparse

# Suspicious TLDs frequently abused in phishing/scams
SUSPICIOUS_TLDS = {
    'xyz', 'top', 'club', 'tk', 'ml', 'ga', 'cf', 'gq', 'work', 
    'click', 'loan', 'fit', 'cricket', 'racing', 'download', 'stream',
    'bid', 'country', 'gdn', 'mom', 'win', 'vip', 'monster', 'rest'
}

# Known URL shorteners that conceal the actual destination
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 
    'buff.ly', 'cutt.ly', 'rebrand.ly', 'tiny.cc', 'shorte.st'
}

# Suspicious keywords indicative of social engineering / phishing
PHISHING_KEYWORDS = [
    'login', 'signin', 'verify', 'account', 'update', 'banking', 
    'security', 'secure', 'wallet', 'password', 'credential', 
    'confirm', 'authenticate', 'free', 'bonus', 'claim', 'prize', 
    'reward', 'urgent', 'suspend', 'billing', 'invoice', 'support-desk'
]

# Common brand targets for typosquatting
TYPOSQUATTING_PATTERNS = [
    r'paypa[l1i]', r'g[o0]{2}gle', r'micr[o0]s[o0]ft', r'amaz[o0]n', 
    r'netfl[i1]x', r'app[l1]e-?id', r'chase-?bank', r'wel[l1]s-?farg[o0]'
]

def analyze_url(url_string):
    """
    Analyzes a URL for malicious indicators, phishing signals, and structural anomalies.
    Returns: dict with risk_level, risk_score, is_malicious, indicators, and details.
    """
    if not url_string:
        return {"error": "URL cannot be empty"}

    url = url_string.strip()
    if not re.match(r'^[a-zA-Z]+://', url):
        # Default scheme for parsing if omitted
        url_to_parse = 'http://' + url
    else:
        url_to_parse = url

    try:
        parsed = urlparse(url_to_parse)
    except Exception as e:
        return {"error": f"Invalid URL format: {str(e)}"}

    netloc = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    full_url = url.lower()

    score = 0
    indicators = []

    # 1. Scheme Check
    if parsed.scheme == 'http':
        score += 15
        indicators.append("Non-secure protocol (HTTP) used instead of encrypted HTTPS.")

    # 2. IP Address in Hostname
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(:\d+)?$'
    if re.match(ip_pattern, netloc):
        score += 40
        indicators.append("Hostname is a direct IP address rather than a registered domain name.")

    # 3. URL Shortener Detection
    hostname_clean = netloc.split(':')[0]
    if hostname_clean in URL_SHORTENERS:
        score += 25
        indicators.append(f"Uses URL shortening service '{hostname_clean}' to mask true target.")

    # 4. Suspicious TLD Detection
    tld = hostname_clean.split('.')[-1] if '.' in hostname_clean else ''
    if tld in SUSPICIOUS_TLDS:
        score += 30
        indicators.append(f"High-risk top-level domain '.{tld}' frequently abused for spam.")

    # 5. Excessive Subdomains or Dots
    dot_count = hostname_clean.count('.')
    if dot_count > 3:
        score += 20
        indicators.append(f"Abnormally high subdomain depth ({dot_count} dots in hostname).")

    # 6. Deceptive @ Symbol (URL obfuscation)
    if '@' in url_to_parse:
        score += 35
        indicators.append("Contains '@' symbol, a common technique to trick browsers into navigating to a hidden host.")

    # 7. Multiple Consecutive Slashes in Path
    if '//' in parsed.path:
        score += 15
        indicators.append("Contains consecutive slashes '//' in URL path (open redirect indicator).")

    # 8. Excessive Length
    if len(url) > 75:
        score += 15
        indicators.append(f"Unusually long URL length ({len(url)} characters).")

    # 9. Hyphens in Hostname
    hyphen_count = hostname_clean.count('-')
    if hyphen_count >= 2:
        score += 15
        indicators.append(f"Multiple hyphens ({hyphen_count}) in domain name (common in phishing).")

    # 10. Phishing / Deceptive Keywords Analysis
    matched_keywords = [kw for kw in PHISHING_KEYWORDS if kw in full_url]
    if matched_keywords:
        score += min(30, len(matched_keywords) * 15)
        indicators.append(f"Contains security-sensitive lure keywords: {', '.join(matched_keywords[:4])}")

    # 11. Brand Impersonation / Typosquatting Check
    for pattern in TYPOSQUATTING_PATTERNS:
        if re.search(pattern, hostname_clean):
            # Check if it's the exact legitimate domain
            if not re.search(r'^(www\.)?(google\.com|paypal\.com|microsoft\.com|amazon\.com|netflix\.com|apple\.com)$', hostname_clean):
                score += 35
                indicators.append("Suspected brand impersonation or typosquatting in hostname.")
                break

    # Calculate final risk score (capped between 5% and 99%)
    risk_score = min(99, max(5, score))

    if risk_score >= 55:
        risk_level = "High Risk"
        verdict = "Phishing / Malicious Link"
        is_malicious = True
    elif risk_score >= 30:
        risk_level = "Suspicious"
        verdict = "Suspicious Link"
        is_malicious = True
    else:
        risk_level = "Low Risk"
        verdict = "Safe / Legitimate Link"
        is_malicious = False

    return {
        "url": url,
        "hostname": hostname_clean,
        "is_malicious": is_malicious,
        "verdict": verdict,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "confidence": risk_score if is_malicious else round(100 - risk_score, 2),
        "indicators": indicators if indicators else ["No suspicious structural anomalies detected.", "Standard domain structure observed."]
    }

