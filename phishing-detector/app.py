from flask import Flask, render_template, request
import re
from urllib.parse import urlparse

app = Flask(__name__)

# ── Suspicious TLDs ──────────────────────────────────────────
SUSPICIOUS_TLDS = [
    '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top',
    '.click', '.link', '.win', '.loan', '.date', '.download',
    '.racing', '.review', '.stream', '.icu', '.cam'
]

BRAND_KEYWORDS = [
    'paypal', 'amazon', 'apple', 'google', 'microsoft',
    'facebook', 'instagram', 'netflix', 'bank', 'secure',
    'account', 'login', 'verify', 'update', 'confirm',
    'ebay', 'chase', 'wellsfargo', 'signin', 'wallet'
]

PHISHING_WORDS = [
    'verify', 'suspended', 'urgent', 'confirm', 'update',
    'validate', 'authenticate', 'unusual', 'activity',
    'limited', 'click-here', 'act-now', 'immediately', 'password',
    'security', 'alert', 'billing', 'transaction', 'login'
]

LOOKALIKE_MAP = {
    '0': 'o',
    '1': 'i',
    '3': 'e',
    '5': 's',
    '7': 't',
    '@': 'a',
    '$': 's',
    '!': 'i'
}

def normalize_text(text):
    """Replace common lookalike characters"""
    for k, v in LOOKALIKE_MAP.items():
        text = text.replace(k, v)
    return text.lower()

def analyze_url(url):
    if not url.startswith('http'):
        url = 'http://' + url

    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or '').lower()
        path = parsed.path + (parsed.query or '')
        protocol = parsed.scheme
    except Exception:
        hostname = url.replace('http://', '').replace('https://', '').split('/')[0].lower()
        path = ''
        protocol = 'http'

    full_url = hostname + path
    normalized_url = normalize_text(full_url)
    normalized_host = normalize_text(hostname)

    risk_score = 0
    reasons = []

    # HTTPS check
    if protocol != 'https':
        risk_score += 15
        reasons.append('No HTTPS encryption — connection not secure')

    # IP address instead of domain
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname):
        risk_score += 25
        reasons.append('Raw IP address used instead of domain name')

    # Suspicious TLD
    if any(normalized_host.endswith(t) for t in SUSPICIOUS_TLDS):
        risk_score += 20
        reasons.append('High-risk or free top-level domain detected')

    # Brand impersonation
    for brand in BRAND_KEYWORDS:
        if brand in normalized_host and not (
            normalized_host == f'{brand}.com' or
            normalized_host.endswith(f'.{brand}.com')
        ):
            risk_score += 30
            reasons.append(f'Brand name "{brand}" appears suspicious or spoofed')
            break

    # Phishing keywords in hostname or path
    for word in PHISHING_WORDS:
        if word in normalized_url:
            risk_score += 20
            reasons.append(f'Phishing keyword "{word}" found in URL')
            break

    # Too many subdomains
    if hostname.count('.') > 3:
        risk_score += 15
        reasons.append('Too many subdomains — common phishing trick')

    # Very long domain
    if len(hostname) > 30:
        risk_score += 10
        reasons.append(f'Unusually long domain name ({len(hostname)} chars)')

    # Multiple hyphens
    if hostname.count('-') > 1:
        risk_score += 12
        reasons.append('Multiple hyphens in domain — suspicious')

    # Long numeric sequences
    if re.search(r'\d{3,}', hostname):
        risk_score += 10
        reasons.append('Long numeric sequence found in domain')

    # Non-ASCII / unicode
    try:
        hostname.encode('ascii')
    except UnicodeEncodeError:
        risk_score += 25
        reasons.append('Non-ASCII / lookalike characters detected in domain')

    # Random-looking string
    if re.search(r'[a-z]{8,}', normalized_host):
        risk_score += 8
        reasons.append('Random long string in domain — suspicious')

    # Cap score at 100
    risk_score = min(risk_score, 100)

    if not reasons:
        reasons.append('No suspicious patterns detected')

    if risk_score >= 50:
        result = '⚠️ PHISHING RISK — Likely dangerous!'
        color = 'danger'
    elif risk_score >= 25:
        result = '⚡ SUSPICIOUS — Proceed with caution!'
        color = 'warning'
    else:
        result = '✅ SAFE — URL appears safe.'
        color = 'safe'

    return result, color, reasons, risk_score

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    color = None
    reasons = []
    risk_score = 0

    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if url:
            result, color, reasons, risk_score = analyze_url(url)

    return render_template(
        'index.html',
        result=result,
        color=color,
        reasons=reasons,
        risk_score=risk_score
    )

if __name__ == '__main__':
    app.run(debug=True)