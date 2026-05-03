# 🛡️ PhishGuard — AI-Powered Phishing URL Detector

PhishGuard is a full-stack web application that analyzes URLs in real time to detect phishing, scam, and malicious websites. It combines a **Machine Learning model**, a **rule-based scoring engine**, and the **Google Safe Browsing API** into a three-tier threat classification system.

> **Threat Levels:** `Safe` · `Suspicious` · `Phishing`

---

## 📸 Features

- 🤖 **ML + Rule Hybrid Engine** — Logistic Regression model trained on a large phishing URL dataset, augmented by a deterministic rule-based scoring layer that can override ML predictions for high-confidence cases.
- 🔍 **Google Safe Browsing Integration** — Checks every URL against Google's live threat intelligence database.
- 📊 **Risk Score (0–100)** — Granular numeric score alongside the classification verdict.
- 🏷️ **Detailed Flags** — Explains exactly *why* a URL was flagged (brand impersonation, free hosting abuse, suspicious keywords, IP-as-host, etc.)
- 🕓 **Recent Scans History** — In-session history of analyzed URLs with one-click reload.
- ⚡ **Fast Response** — All checks run in parallel with a 5-second timeout per external call.

---

## 🏗️ Architecture

```
┌────────────────────────────────────────────────────────┐
│                    Browser (React)                     │
│              frontend/  — Vite + React 19              │
└──────────────────────┬─────────────────────────────────┘
                       │ POST /api/check-url
                       ▼
┌────────────────────────────────────────────────────────┐
│              Express API  (Node.js)                    │
│                   backend/server.js                    │
│                                                        │
│  1. Google Safe Browsing API  ──► instant blacklist    │
│  2. ML micro-service          ──► risk score + flags   │
│  3. Rule-based engine         ──► explanations         │
└──────────────────────┬─────────────────────────────────┘
                       │ POST /predict
                       ▼
┌────────────────────────────────────────────────────────┐
│           Python Flask ML Service                      │
│                 ml-service/app.py                      │
│                                                        │
│  • TF-IDF character n-gram vectorizer                  │
│  • Logistic Regression (sklearn)                       │
│  • Rule-based scoring layer (overrides ML)             │
└────────────────────────────────────────────────────────┘
```

| Layer | Tech | Port |
|---|---|---|
| Frontend | React 19, Vite, Lucide Icons | `5173` (dev) |
| Backend API | Node.js, Express 5, Axios | `5000` |
| ML Service | Python, Flask, scikit-learn | `5001` |

---

## 📁 Project Structure

```
phishing/
├── .gitignore                  # Root-level gitignore
├── README.md
│
├── frontend/                   # React + Vite SPA
│   ├── src/
│   │   └── App.jsx             # Main UI component
│   ├── .env                    # Local env (not committed)
│   ├── .env.example            # Template — commit this
│   ├── .gitignore
│   └── package.json
│
├── backend/                    # Express REST API
│   ├── server.js               # Main server + all logic
│   ├── .env                    # Local env (not committed)
│   ├── .env.example            # Template — commit this
│   ├── .gitignore
│   └── package.json
│
└── ml-service/                 # Python Flask ML micro-service
    ├── app.py                  # Flask server + rule engine
    ├── train_model.py          # Model training script
    ├── clean_data.py           # Dataset cleaning script
    ├── test_model.py           # Quick model sanity check
    ├── templates/
    │   └── index.html          # Standalone Flask UI
    ├── .gitignore
    # ── NOT committed (too large / binary) ──
    # model.pkl                 # Trained LR model (~4 MB)
    # vectorizer.pkl            # TF-IDF vectorizer (~10 MB)
    # data.csv                  # Raw dataset (~47 MB)
    # data_clean.csv            # Cleaned dataset (~40 MB)
    # archive.zip               # Original downloaded archive
```

---

## 🚀 Getting Started

### Prerequisites

| Tool | Minimum Version |
|---|---|
| Node.js | 18+ |
| npm | 9+ |
| Python | 3.9+ |
| pip | latest |

---

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/phishguard.git
cd phishguard
```

---

### 2. Backend Setup (Node.js)

```bash
cd backend
npm install
```

Create your `.env` file from the template:

```bash
copy .env.example .env      # Windows
# or
cp .env.example .env        # macOS / Linux
```

Edit `backend/.env`:

```env
GOOGLE_SAFE_BROWSING_API_KEY=your_api_key_here
PORT=5000
ML_SERVICE_URL=http://127.0.0.1:5001
```

> **Getting a Google Safe Browsing API Key:**
> 1. Go to [Google Cloud Console](https://console.cloud.google.com/)
> 2. Enable the **Safe Browsing API**
> 3. Create an API key under **Credentials**
>
> The app works without a key (uses a small dummy blacklist for testing), but real-world use requires one.

Start the backend:

```bash
node server.js
```

The API will be available at `http://localhost:5000`.

---

### 3. Frontend Setup (React + Vite)

```bash
cd frontend
npm install
```

Create your `.env` file:

```bash
copy .env.example .env      # Windows
# or
cp .env.example .env        # macOS / Linux
```

Edit `frontend/.env`:

```env
VITE_API_URL=http://127.0.0.1:5000
```

Start the dev server:

```bash
npm run dev
```

The app will be available at `http://localhost:5173`.

---

### 4. ML Service Setup (Python)

```bash
cd ml-service
```

Create and activate a virtual environment (recommended):

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install flask flask-cors scikit-learn joblib pandas
```

#### Option A — Use Pre-trained Model Files

If you have received `model.pkl` and `vectorizer.pkl` (via shared storage, Git LFS, etc.), place them in the `ml-service/` directory and start the service:

```bash
python app.py
```

#### Option B — Train the Model Yourself

You need the dataset first. Download a phishing URL dataset (e.g. from [Kaggle](https://www.kaggle.com/)) and save it as `data.csv` in `ml-service/`. The CSV must have at minimum:

| Column | Description |
|---|---|
| `url` | The URL string |
| `label` | `0` = Safe, `1` = Phishing |

Then run:

```bash
# Step 1 — Clean the raw data
python clean_data.py

# Step 2 — Train the model (outputs model.pkl + vectorizer.pkl)
python train_model.py

# Step 3 — Start the service
python app.py
```

The ML service will be available at `http://localhost:5001`.

---

### 5. Run Everything Together

Open **three terminals** simultaneously:

```bash
# Terminal 1 — ML Service
cd ml-service && python app.py

# Terminal 2 — Backend API
cd backend && node server.js

# Terminal 3 — Frontend
cd frontend && npm run dev
```

Then open `http://localhost:5173` in your browser.

---

## ⚙️ Environment Variables Reference

### `backend/.env`

| Variable | Required | Default | Description |
|---|---|---|---|
| `GOOGLE_SAFE_BROWSING_API_KEY` | No* | — | Google Safe Browsing API key. Without it, a small dummy blacklist is used. |
| `PORT` | No | `5000` | Port the Express server listens on. |
| `ML_SERVICE_URL` | No | `http://127.0.0.1:5001` | Base URL of the Python ML micro-service. |

*Strongly recommended for production.

### `frontend/.env`

| Variable | Required | Default | Description |
|---|---|---|---|
| `VITE_API_URL` | Yes | — | Full base URL of the Express backend API. |

---

## 🧠 How the Detection Engine Works

Every URL submitted goes through three sequential checks:

### Stage 1 — Google Safe Browsing (Hard Block)
The URL is sent to Google's Safe Browsing Threat Matches API. If a match is found, the URL is immediately classified as **Phishing (Score: 99)** and no further analysis is performed.

### Stage 2 — Machine Learning (TF-IDF + Logistic Regression)
The URL is normalized (lowercased, scheme and `www.` stripped) and transformed using a **character-level TF-IDF vectorizer** with n-grams of size 3–5. A Logistic Regression model outputs a **phishing probability** (`ml_confidence`).

### Stage 3 — Rule-Based Scoring Engine

The rule engine produces an **integer risk score from 0–100**. Rules fire independently and scores stack:

| Rule | Points |
|---|---|
| Each suspicious keyword found (capped at 3) | +20 each |
| Hosted on a known free hosting platform | +25 |
| Free hosting **and** keyword combo (hard floor: 75) | +50 extra |
| URL length ≥ 75 characters | +10 |
| URL length ≥ 100 characters | +10 (stacks) |
| ≥ 4 dots in the URL | +10 |
| ≥ 3 hyphens in the domain | +10 |
| `@` symbol in the URL | +20 |
| IP address used as host | +25 |
| ML confidence ≥ 75% | +20 |

**Final Classification:**

| Risk Score | Verdict |
|---|---|
| > 50 | 🔴 Phishing |
| 30 – 50 | 🟡 Suspicious |
| < 30 | 🟢 Safe |

---

## 🌐 API Reference

### `POST /api/check-url`

**Request:**
```json
{
  "url": "http://example-suspicious-login.com/verify"
}
```

**Response:**
```json
{
  "prediction": "Phishing",
  "riskScore": 85,
  "reasons": [
    "Passed Google Safe Browsing check.",
    "ML + Rules analysis: Phishing (Risk Score: 85/100, ML confidence: 82.3%)",
    "Suspicious keyword(s) found: login, verify",
    "Possible brand impersonation detected (google).",
    "URL is unusually long, which can hide suspicious parts."
  ]
}
```

| Field | Type | Description |
|---|---|---|
| `prediction` | `string` | `"Safe"` \| `"Suspicious"` \| `"Phishing"` |
| `riskScore` | `number` | Integer 0–100 |
| `reasons` | `string[]` | Human-readable explanation list |

---

## 🔒 Security Notes

- **Never commit your `.env` files.** They are excluded by `.gitignore` at root, backend, and frontend levels.
- The `.env.example` files are safe to commit — they contain no real credentials.
- Your **Google Safe Browsing API key** must stay private. Rotate it immediately if it is ever accidentally exposed.
- The ML model files (`model.pkl`, `vectorizer.pkl`) and dataset files (`*.csv`, `*.zip`) are excluded from git due to their size. Use a shared drive, Git LFS, or re-train locally.

---

## 📦 Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 19, Vite 8, Lucide React |
| Backend | Node.js, Express 5, Axios, dotenv |
| ML Service | Python 3, Flask, Flask-CORS, scikit-learn, joblib, pandas |
| ML Model | Logistic Regression with TF-IDF character n-grams |
| Threat Intel | Google Safe Browsing API v4 |

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m "feat: add my feature"`
4. Push to the branch: `git push origin feature/my-feature`
5. Open a Pull Request

---

## 📄 License

This project is licensed under the **ISC License**.
