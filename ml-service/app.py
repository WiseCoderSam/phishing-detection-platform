from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import joblib
import re

app = Flask(__name__)
CORS(app)

# Load the trained model and vectorizer
try:
    model = joblib.load("model.pkl")
    vectorizer = joblib.load("vectorizer.pkl")
except Exception as e:
    print(f"CRITICAL: Could not load model or vectorizer. Error: {e}")

# ── Rule-based scoring ────────────────────────────────────────────────────────

# High-risk keywords that strongly suggest a scam or phishing page
HIGH_RISK_KEYWORDS = [
    "free", "money", "login", "verify", "update", "bank", "secure",
    "account", "win", "bonus", "prize", "winner", "click", "confirm",
    "password", "credential", "signin", "sign-in", "webscr", "suspend",
    "limited", "urgent", "alert", "offer", "reward", "gift", "claim",
]

# Platforms that legitimately host user content but are commonly abused for phishing
FREE_HOSTING_DOMAINS = [
    "sites.google.com",
    "github.io",
    "wixsite.com",
    "weebly.com",
    "blogspot.com",
    "web.app",
    "firebaseapp.com",
    "netlify.app",
    "vercel.app",
    "glitch.me",
    "pages.dev",
    "onrender.com",
    "mystrikingly.com",
    "carrd.co",
]


def analyze_url(cleaned_url: str, ml_confidence: float) -> dict:
    """
    Apply rule-based analysis on top of ML output.

    Scoring (integer points, out of 100):
      - Each suspicious keyword found      : +20 (capped at 3 keywords = +60)
      - Free hosting domain detected       : +25
      - Free hosting + keyword combo       : +50 (overrides ML to HIGH RISK)
      - URL length >= 75                   : +10
      - URL length >= 100                  : +10 (stacks)
      - >= 4 dots in URL                   : +10
      - >= 3 hyphens in domain             : +10
      - '@' symbol in URL                  : +20
      - IP address as host                 : +25
      - ML confidence >= 75%              : +20 (ML strongly says phishing)

    Classification:
      risk_score > 50  → Phishing
      risk_score 30-50 → Suspicious
      risk_score < 30  → Safe
      
    Override rules (highest priority):
      - Free hosting + ANY keyword         → minimum risk_score = 75 (Phishing)
      - ML confidence < 75% alone          → cannot be marked Safe by ML alone
    """
    risk_score = 0
    flags = []

    url_lower = cleaned_url.lower()

    # ── 1. Keyword check ──────────────────────────────────────────────────────
    matched_keywords = [kw for kw in HIGH_RISK_KEYWORDS if kw in url_lower]
    keyword_score = min(len(matched_keywords), 3) * 20  # cap at +60
    if matched_keywords:
        risk_score += keyword_score
        flags.append(f"Suspicious keyword(s) found: {', '.join(matched_keywords[:5])}")

    # ── 2. Free hosting check ─────────────────────────────────────────────────
    on_free_host = False
    for domain in FREE_HOSTING_DOMAINS:
        if url_lower.startswith(domain) or ("." + domain) in url_lower:
            on_free_host = True
            risk_score += 25
            flags.append(f"Hosted on free platform ({domain}) commonly abused for phishing")
            break

    # ── 3. Combo override — free hosting + keywords = HIGH RISK ──────────────
    if on_free_host and matched_keywords:
        risk_score += 50  # additional combo penalty
        flags.append("HIGH RISK: Free hosting platform combined with suspicious keywords")
        # Hard floor: always at least 75 regardless of ML
        risk_score = max(risk_score, 75)

    # ── 4. Structural checks ──────────────────────────────────────────────────
    if len(cleaned_url) >= 75:
        risk_score += 10
        flags.append("Unusually long URL")
    if len(cleaned_url) >= 100:
        risk_score += 10
        flags.append("Very long URL (>= 100 chars)")

    dot_count = url_lower.count('.')
    if dot_count >= 4:
        risk_score += 10
        flags.append(f"Many dots in URL ({dot_count})")

    host = url_lower.split('/')[0]
    hyphen_count = host.count('-')
    if hyphen_count >= 3:
        risk_score += 10
        flags.append(f"Excessive hyphens in domain ({hyphen_count})")

    if '@' in url_lower:
        risk_score += 20
        flags.append("'@' symbol detected in URL (credential bypass trick)")

    if re.match(r'^\d{1,3}(\.\d{1,3}){3}', host):
        risk_score += 25
        flags.append("IP address used as host instead of domain name")

    # ── 5. ML confidence contribution ────────────────────────────────────────
    # ML gets a vote only when it's confident (>= 75%)
    if ml_confidence >= 0.75:
        risk_score += 20
        flags.append(f"ML model is highly confident this is phishing ({round(ml_confidence*100,1)}%)")
    elif ml_confidence < 0.75 and not on_free_host and not matched_keywords:
        # ML is uncertain and no rules fired → mark safe
        pass  # no additional score added

    # ── 6. Classify ──────────────────────────────────────────────────────────
    risk_score = min(risk_score, 100)

    if risk_score > 50:
        label = "Phishing"
    elif risk_score >= 30:
        label = "Suspicious"
    else:
        label = "Safe"

    return {
        "label": label,
        "risk_score": risk_score,
        "flags": flags,
        "on_free_host": on_free_host,
        "keyword_hits": matched_keywords,
    }


def clean_url(url: str) -> str:
    """Normalize URL for prediction: lowercase, strip scheme and www."""
    url = str(url).lower().strip()
    url = re.sub(r'^https?://', '', url)
    url = re.sub(r'^www\.', '', url)
    return url


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/', methods=['GET'])
def home():
    return render_template('index.html')


@app.route('/predict', methods=['POST'])
def predict():
    # Handle both JSON (from React/Node backend) and Form Data (from Flask template)
    if request.is_json:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        url = data['url']
    else:
        url = request.form.get('url')
        if not url:
            return render_template('index.html', error="URL is required")

    url = url.strip()
    if not url:
        return render_template('index.html', error="URL is required")

    # Preprocess
    cleaned_url = clean_url(url)
    url_vec = vectorizer.transform([cleaned_url])

    # ML score — probability that this URL is phishing (class 1)
    probabilities = model.predict_proba(url_vec)[0]
    ml_confidence = float(probabilities[1])   # P(phishing)

    # Rule-based analysis — overrides ML when high-confidence rules fire
    analysis = analyze_url(cleaned_url, ml_confidence)

    result_text = analysis["label"]
    risk_score   = analysis["risk_score"]
    flags        = analysis["flags"]

    if request.is_json:
        return jsonify({
            'prediction': 1 if result_text == "Phishing" else (2 if result_text == "Suspicious" else 0),
            'confidence': risk_score,           # risk score as the confidence metric
            'result': result_text,
            'ml_score': round(ml_confidence * 100, 2),
            'risk_score': risk_score,
            'flags': flags,
        })
    else:
        return render_template(
            'index.html',
            result=result_text,
            confidence=risk_score,
            url=url,
            flags=flags,
        )


if __name__ == '__main__':
    app.run(port=5001, debug=True)