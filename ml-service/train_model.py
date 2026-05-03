import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
import joblib
import re
from urllib.parse import urlparse

# Trusted root domains that should never be labeled phishing
TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "gmail.com", "googlemail.com",
    "amazon.com", "amazonaws.com",
    "microsoft.com", "live.com", "outlook.com", "hotmail.com",
    "apple.com", "icloud.com",
    "facebook.com", "instagram.com", "whatsapp.com",
    "twitter.com", "x.com",
    "linkedin.com",
    "github.com", "githubusercontent.com",
    "dropbox.com",
    "paypal.com",
    "netflix.com",
    "adobe.com",
    "cloudflare.com",
    "wordpress.com", "wordpress.org",
    "wikipedia.org", "wikimedia.org",
}

# Matches IPv6 addresses like [::1], [2001:db8::1], etc.
IPV6_RE = re.compile(r'^\[([^\]]*)\]')


def extract_root_domain(url: str) -> str:
    try:
        url = str(url).lower().strip()
        url = re.sub(r'^https?://', '', url)

        # If the host portion is an IPv6 literal e.g. [::1]/path,
        # pull out just the address and return it — it will never
        # match a trusted domain so the row is kept as-is.
        ipv6_match = IPV6_RE.match(url)
        if ipv6_match:
            return ipv6_match.group(1)  # e.g. "::1"

        host = urlparse("http://" + url).netloc
        host = host.split(':')[0]
        host = re.sub(r'^www\.', '', host)

        parts = host.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return host
    except Exception:
        return ""


def clean_url(url: str) -> str:
    """Normalise URL for TF-IDF: lowercase, strip scheme and www."""
    url = str(url).lower().strip()
    url = re.sub(r'^https?://', '', url)
    url = re.sub(r'^www\.', '', url)
    return url


# Load data
print("Loading dataset...")
df = pd.read_csv("data_clean.csv", encoding="utf-8-sig")
df.columns = df.columns.str.strip()

# Domain extraction
print("Analyzing domains and filtering contaminated samples...")
df['root_domain'] = df['url'].apply(extract_root_domain)

# Filter out contaminated samples
contaminated_mask = (df['root_domain'].isin(TRUSTED_DOMAINS)) & (df['label'] == 1)
n_removed = contaminated_mask.sum()
df = df[~contaminated_mask].reset_index(drop=True)
print(f"Removed {n_removed} contaminated samples (trusted domain labelled phishing).")
print(f"Final training set size: {len(df)}")

# Features / target
X = df['url'].apply(clean_url)
y = df['label']

# Train / test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Vectorise
print("Vectorizing URLs (this may take a minute)...")
vectorizer = TfidfVectorizer(
    analyzer='char',
    ngram_range=(3, 5),
    min_df=10,
    sublinear_tf=True,
)
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

# Train
print("Training Logistic Regression model...")
model = LogisticRegression(max_iter=1000, C=0.5, class_weight='balanced')
model.fit(X_train_vec, y_train)

# Evaluate
print("\nEvaluation Results:")
y_pred = model.predict(X_test_vec)
print(f"Overall Accuracy: {accuracy_score(y_test, y_pred):.4f}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=["Safe", "Phishing"]))

# Save
joblib.dump(model, "model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")
print("\nMODEL AND VECTORIZER SAVED SUCCESSFULLY")