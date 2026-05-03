require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { URL } = require('url');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// Known sensitive brand names often impersonated in phishing
const TARGET_BRANDS = ['paypal', 'google', 'facebook', 'amazon', 'apple', 'bank', 'microsoft', 'netflix'];

// Keywords frequently used in phishing URLs
const SUSPICIOUS_KEYWORDS = ['login', 'verify', 'update', 'secure', 'account', 'banking', 'auth', 'confirm'];

// 1. Google Safe Browsing API Integration
async function checkSafeBrowsing(url) {
  // Read from .env file
  const API_KEY = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

  // If no API key is provided, we simulate the check for testing/education purposes.
  // We'll hardcode some known bad domains to simulate a blacklist hit if no key exists.
  const dummyBlacklist = ['paypal-login-security-update.com', 'evil-phishing-site.net'];

  if (!API_KEY) {
    try {
      const parsedUrl = new URL(url);
      if (dummyBlacklist.includes(parsedUrl.hostname)) {
        return true; // Blacklisted
      }
      return false; // Safe
    } catch (e) {
      return false;
    }
  }

  // Real API implementation
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
      {
        timeout: 5000
      }
    );

    // If matches is present, it's flagged
    return response.data && response.data.matches && response.data.matches.length > 0;
  } catch (error) {
    if (error.code === 'ECONNABORTED') {
      console.error("Safe Browsing request timed out");
    } else {
      console.error("Safe Browsing API Error:", error.message);
    }
    return false; // Fail open for the sake of the app if API fails
  }
}

// 2. Machine Learning API Check
async function checkMLService(inputURL) {
  try {
    const ML_URL = process.env.ML_SERVICE_URL || 'http://127.0.0.1:5001';
    console.log(`[DEBUG] Sending ML request for URL: ${inputURL} to ${ML_URL}/predict`);
    const response = await axios.post(
      `${ML_URL}/predict`,
      { url: inputURL },
      { timeout: 5000 }
    );
    console.log(`[DEBUG] Received ML response:`, response.data);
    return response.data; // { result: 'Safe'|'Suspicious'|'Phishing', risk_score, ml_score, flags }
  } catch (error) {
    if (error.code === 'ECONNABORTED') {
      console.error("[DEBUG] ML request timed out");
    } else {
      console.error("[DEBUG] ML Service Error:", error.message);
    } return null; // Fallback response to prevent crash
  }
}

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
    console.log("Checking Google Safe Browsing for:", processedUrl);
    const isBlacklisted = await checkSafeBrowsing(processedUrl);
    console.log("Blacklist result:", isBlacklisted);
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
    
    if (mlResult) {
      // Use the authoritative result and risk_score from the Python service
      prediction = mlResult.result || 'Safe';          // 'Safe' | 'Suspicious' | 'Phishing'
      riskScore  = mlResult.risk_score ?? 0;           // integer 0-100

      const mlPct = mlResult.ml_score ?? 0;
      reasons.push(`ML + Rules analysis: ${prediction} (Risk Score: ${riskScore}/100, ML confidence: ${mlPct.toFixed(1)}%)`);

      // Surface rule-based flags as individual reasons
      if (Array.isArray(mlResult.flags)) {
        mlResult.flags.forEach(flag => reasons.push(flag));
      }
    } else {
      reasons.push('ML Service unavailable, relying on rule-based fallback.');
      prediction = 'Suspicious'; // Fallback
      riskScore = 50;
    }

    // Helper to only add negative rules if we are already flagging as phishing.
    // This prevents rules from contradicting a 'Safe' ML decision.
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

    // 2. Brand Impersonation Check
    TARGET_BRANDS.forEach((brand) => {
      // If the brand name appears anywhere in the URL
      if (fullUrlLower.includes(brand)) {
        const domainParts = hostname.split('.');
        const rootDomain = domainParts.slice(-2).join('.');
        
        // Exact official domain check
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

    // Final UI Consistency Check
    if (prediction === 'Phishing' && reasons.length <= 2) {
        reasons.push('Hidden anomalies detected by Machine Learning pattern recognition.');
    }

    if (prediction === 'Safe') {
        reasons.push('No obvious suspicious features detected based on AI rules.');
    }

    res.json({
      prediction,
      riskScore,
      reasons: [...new Set(reasons)] // Unique reasons
    });

  } catch (error) {
    res.status(400).json({ error: 'Invalid URL provided. Please enter a valid website link.' });
  }
});

app.listen(PORT, () => {
  console.log("SERVER STARTED");
  console.log(`Running on http://localhost:${PORT}`);
});

setInterval(() => {
  console.log("Server still running...");
}, 10000);