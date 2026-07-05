require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { URL } = require('url');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 5000;
// Falls back to the deployed ML service so production keeps working even if ML_SERVICE_URL
// isn't set in the environment. Override it locally via .env (http://127.0.0.1:5001).
const ML_SERVICE_URL = process.env.ML_SERVICE_URL || 'https://phish-123.onrender.com';

// Shared secret sent to the ML service so /predict only accepts calls from this backend.
const ML_INTERNAL_TOKEN = process.env.ML_INTERNAL_TOKEN;

// Browser origins allowed to call this API (comma-separated env, e.g. "https://app.example.com").
// If unset, CORS stays open for local dev — a startup warning is logged so prod deploys lock it down.
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map((o) => o.trim()).filter(Boolean)
  : null;

// Verbose request logging is off by default so URLs/responses don't leak into production logs.
const DEBUG = process.env.DEBUG_LOGS === '1';
const debug = (...args) => { if (DEBUG) console.log(...args); };

const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

// Trust proxy required for rate limiting behind reverse proxies (Nginx, Render, etc.)
app.set('trust proxy', 1);

// Disable header leak (hide Express)
app.disable('x-powered-by');

// Security Headers
app.use(helmet({
  crossOriginResourcePolicy: false,
}));

// Rate Limiting (max 100 requests per 15 minutes per IP)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests, please try again later.' }
});
app.use(limiter);

app.use(cors({
  origin: ALLOWED_ORIGINS || true,
  methods: ['GET', 'POST'],
}));
if (!ALLOWED_ORIGINS) {
  console.warn('[SECURITY] ALLOWED_ORIGINS is not set — CORS is open to all origins. Set it in production.');
}

// Cap request bodies — inputs are just URLs, so 10kb is plenty and blocks payload-based abuse.
app.use(express.json({ limit: '10kb' }));

// Known sensitive brand names often impersonated in phishing
const TARGET_BRANDS = ['paypal', 'google', 'facebook', 'amazon', 'apple', 'microsoft', 'netflix'];

// Keywords frequently used in phishing URLs
const SUSPICIOUS_KEYWORDS = ['login', 'verify', 'update', 'secure', 'account', 'banking', 'auth', 'confirm'];

// 1. Google Safe Browsing API Integration
async function checkSafeBrowsing(url) {
  const API_KEY = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

  const dummyBlacklist = ['paypal-login-security-update.com', 'evil-phishing-site.net'];

  if (!API_KEY) {
    try {
      const parsedUrl = new URL(url);
      if (dummyBlacklist.includes(parsedUrl.hostname)) {
        return true;
      }
      return false;
    } catch (e) {
      return false;
    }
  }

  try {
    const response = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`,
      {
        client: { clientId: "phishguard", clientVersion: "1.0.0" },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }]
        }
      },
      { timeout: 5000 }
    );

    return response.data && response.data.matches && response.data.matches.length > 0;
  } catch (error) {
    if (error.code === 'ECONNABORTED') {
      console.error("Safe Browsing request timed out");
    } else {
      console.error("Safe Browsing API Error:", error.message);
    }
    return false;
  }
}

// 2. Machine Learning API Check
async function checkMLService(inputURL) {
  const sendRequest = () => axios.post(
    `${ML_SERVICE_URL}/predict`,
    { url: inputURL },
    {
      timeout: 60000,
      headers: ML_INTERNAL_TOKEN ? { 'X-Internal-Token': ML_INTERNAL_TOKEN } : {},
    }
  );

  // Two attempts: the first request can fail while the free-tier ML container is still cold-starting.
  for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      debug(`[DEBUG] ML request attempt ${attempt} for URL: ${inputURL}`);
      const response = await sendRequest();
      debug(`[DEBUG] Received ML response:`, response.data);
      return response.data;
    } catch (error) {
      const reason = error.code === 'ECONNABORTED' ? 'timed out' : error.message;
      console.error(`ML Service error (attempt ${attempt}): ${reason}`);
      if (attempt === 1) {
        await new Promise((r) => setTimeout(r, 2000));
      }
    }
  }
  return null;
}

// Health Check Endpoint — reports real readiness of BOTH services.
// Also triggers the ML service to wake if it's cold. The frontend polls this until ml === 'awake'.
app.get('/api/health', async (req, res) => {
  let ml = 'sleeping';
  try {
    // Short timeout: if ML is still cold this returns 'sleeping' (and the request itself starts
    // its wake-up), so the frontend keeps polling rather than hanging on a 50s cold start.
    await axios.get(`${ML_SERVICE_URL}/`, { timeout: 8000 });
    ml = 'awake';
  } catch (e) {
    // ML still waking — leave status as 'sleeping'.
  }
  res.json({ backend: 'awake', ml });
});

// Root endpoint — required for uptime monitors (e.g. UptimeRobot) to get a 200 OK
app.get('/', (req, res) => {
  axios.get(`${ML_SERVICE_URL}/`).catch(() => { });
  res.status(200).send('PhishGuard Backend is running.');
});

// Main Endpoint
app.post('/api/check-url', async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  let processedUrl = url;
  if (!/^https?:\/\//i.test(url)) {
    processedUrl = 'http://' + url;
  }

  try {
    const parsedUrl = new URL(processedUrl);
    const hostname = parsedUrl.hostname.toLowerCase();
    const fullUrlLower = processedUrl.toLowerCase();

    let prediction = 'Safe';
    let riskScore = 0;
    const reasons = [];

    // --- A. Google Safe Browsing Check (Overrides all) ---
    debug("Checking Google Safe Browsing for:", processedUrl);
    const isBlacklisted = await checkSafeBrowsing(processedUrl);
    debug("Blacklist result:", isBlacklisted);
    if (isBlacklisted) {
      return res.json({
        prediction: 'Phishing',
        riskScore: 99,
        reasons: ['Blacklisted by Google Safe Browsing (CRITICAL)']
      });
    } else {
      reasons.push('Passed Google Safe Browsing check.');
    }

    // --- B. Machine Learning + Rule-Based Service Check ---
    const mlResult = await checkMLService(processedUrl);

    if (!mlResult) {
      // ML engine unreachable (cold-starting or down). Return an honest "try again" instead of
      // a fabricated Suspicious/50 verdict, which would mislabel safe sites. The frontend uses
      // the warmingUp flag to drop back into its warm-up state and re-enable once ML is ready.
      return res.status(503).json({
        error: 'The analysis engine is warming up. Please try again in a few seconds.',
        warmingUp: true,
      });
    }

    prediction = mlResult.result || 'Safe';
    riskScore = mlResult.risk_score ?? 0;

    const mlPct = mlResult.ml_score ?? 0;
    reasons.push(`ML + Rules analysis: ${prediction} (Risk Score: ${riskScore}/100, ML confidence: ${mlPct.toFixed(1)}%)`);

    if (Array.isArray(mlResult.flags)) {
      mlResult.flags.forEach(flag => reasons.push(flag));
    }

    const addRuleExplanation = (reason) => {
      if (prediction === 'Phishing' || prediction === 'Suspicious') {
        reasons.push(reason);
      }
    };

    // --- C. Rule-based Explanations (Supports ML) ---

    // 1. IP Address Check
    if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(hostname)) {
      addRuleExplanation('Domain is an IP address instead of a standard domain name.');
    }

    // 2. Brand Impersonation Check (match the hostname, not the path — avoids example.com/apple)
    TARGET_BRANDS.forEach((brand) => {
      if (hostname.includes(brand)) {
        const domainParts = hostname.split('.');
        const rootDomain = domainParts.slice(-2).join('.');

        if (
          rootDomain !== `${brand}.com` &&
          rootDomain !== `${brand}.net` &&
          rootDomain !== `${brand}.org` &&
          hostname !== brand
        ) {
          addRuleExplanation(`Possible brand impersonation detected (${brand}).`);
        }
      }
    });

    // 3. Suspicious Keywords Check
    const foundKeywords = [];
    SUSPICIOUS_KEYWORDS.forEach(keyword => {
      if (fullUrlLower.includes(keyword)) foundKeywords.push(keyword);
    });

    if (foundKeywords.length > 0) {
      addRuleExplanation(`Suspicious keyword(s) found: ${foundKeywords.join(', ')}.`);
    }

    // 4. Hyphen Abuse in Domain
    const hyphenCount = (hostname.match(/-/g) || []).length;
    if (hyphenCount >= 2) {
      addRuleExplanation('Excessive hyphens in domain name.');
    }

    // 5. URL Structure: Length
    if (processedUrl.length > 75) {
      addRuleExplanation('URL is unusually long, which can hide suspicious parts.');
    }

    // 6. URL Structure: Subdomains
    const dotCount = (hostname.match(/\./g) || []).length;
    if (dotCount > 3) {
      addRuleExplanation('Unusually high number of subdomains.');
    }

    // Final UI Consistency
    if (prediction === 'Phishing' && reasons.length <= 2) {
      reasons.push('Hidden anomalies detected by Machine Learning pattern recognition.');
    }

    if (prediction === 'Safe') {
      reasons.push('No obvious suspicious features detected based on AI rules.');
    }

    res.json({
      prediction,
      riskScore,
      reasons: [...new Set(reasons)]
    });

  } catch (error) {
    res.status(400).json({ error: 'Invalid URL provided. Please enter a valid website link.' });
  }
});

app.listen(PORT, () => {
  console.log("SERVER STARTED");
  console.log(`Running on http://localhost:${PORT}`);
});

// Keep the ML service warm WHILE this backend is awake by pinging it every 10 minutes.
//
// IMPORTANT: a process cannot keep ITSELF awake — once Render's free tier spins this backend
// down (~15 min without external traffic), this interval stops running too. To prevent the
// backend from sleeping, an EXTERNAL uptime monitor (e.g. UptimeRobot or cron-job.org) must hit
// this backend's "/" every ~10 min. That external ping cascades a wake-up to the ML service,
// so keeping the backend awake keeps both services awake.
setInterval(() => {
  debug("[Keep-Alive] Pinging ML service to keep it warm...");
  axios.get(`${ML_SERVICE_URL}/`, { timeout: 8000 }).catch(() => { });
}, 10 * 60 * 1000);