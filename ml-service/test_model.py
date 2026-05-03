import joblib
import re

model = joblib.load("model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

def test(url):
    url = url.lower()
    url = re.sub(r'^https?://', '', url)
    url = re.sub(r'^www\.', '', url)

    vec = vectorizer.transform([url])
    prob = model.predict_proba(vec)[0][1]

    print(url, "->", "Phishing" if prob >= 0.5 else "Safe", f"({round(prob*100,2)}%)")

test("google.com")
test("amazon.com")
test("paypal-login-security-update.com")
test("https://sites.google.com/view/free-money")