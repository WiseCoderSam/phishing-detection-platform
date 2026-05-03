import { useState } from 'react';
import {
  Shield, ShieldAlert, ShieldCheck, Link2, Loader2, AlertCircle, TriangleAlert,
  CheckCircle2, XCircle, Lock, Code, Hash, Globe, Activity
} from 'lucide-react';

function App() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [recentScans, setRecentScans] = useState([]);

  const handleCheck = async (e) => {
    e.preventDefault();

    if (!url.trim()) {
      return setError('Please enter a URL.');
    }

    // 🔥 URL format validation
    try {
      new URL(url.startsWith('http') ? url : 'http://' + url);
    } catch {
      return setError('Please enter a valid URL (e.g., example.com)');
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const response = await fetch(`${import.meta.env.VITE_API_URL}/api/check-url`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url })
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.error || 'Failed to connect to the server.');
      }

      const newResult = await response.json();

      // generate scanId ONCE
      newResult.scanId = Math.random().toString(36).substring(2, 10).toUpperCase();
      setResult(newResult);

      setRecentScans(prev => {
        // Prevent duplicate immediate recent scans
        const filtered = prev.filter(scan => scan.url !== url);
        return [{ url, result: newResult, time: new Date().toLocaleTimeString() }, ...filtered];
      });
    } catch (err) {
      setResult(null); // 🔥 clears old result (IMPORTANT)
      setError(err.message || 'Connection failed. No analysis was performed.');
    } finally {
      setLoading(false);
    }
  };

  const handleRecentClick = (scan) => {
    setUrl(scan.url);
    setResult(scan.result);
  };

  const generateChecks = (reasons = []) => {
    return [
      { id: 'blacklist', label: 'Safe Browsing Blacklist', passed: !reasons.some(r => r.includes('Blacklisted')), desc: 'Not flagged by Google' },
      { id: 'ml', label: 'Machine Learning Analysis', passed: !reasons.some(r => r.includes('model flagged')), desc: 'AI anomaly detection' },
      { id: 'brand', label: 'Possible brand impersonation', passed: !reasons.some(r => r.includes('impersonation detected')), desc: 'Matches official domain' },
      { id: 'keywords', label: 'Suspicious Keywords', passed: !reasons.some(r => r.includes('Suspicious keyword')), desc: 'No deceptive terms' },
      { id: 'hyphens', label: 'Domain Hyphens', passed: !reasons.some(r => r.includes('Excessive hyphens')), desc: 'Standard hyphen usage' },
      { id: 'subdomains', label: 'Subdomains Count', passed: !reasons.some(r => r.includes('high number of subdomains')), desc: 'Normal subdomain depth' },
    ];
  };

  const getGradient = (score) => {
    if (score <= 15) return 'linear-gradient(90deg, var(--success), var(--success))';
    if (score <= 40) return 'linear-gradient(90deg, var(--success), var(--warning))';
    return 'linear-gradient(90deg, var(--success), var(--warning), var(--danger))';
  };

  const getWidth = (score) => {
    return `${Math.max(5, Math.min(score, 100))}%`;
  };

  return (
    <div className="app-container">
      <div className="header">
        <Shield className="header-icon" size={80} />
        <h1>PhishGuard</h1>
        <p>AI-Powered Phishing Link Detector</p>
      </div>

      <div className="card">
        <form onSubmit={handleCheck}>
          <div className="input-group">
            <Link2 className="input-icon" size={28} />
            <input
              type="text"
              className="url-input"
              placeholder="Enter website URL (e.g., example.com)"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              disabled={loading}
            />
          </div>

          <button type="submit" className="check-btn" disabled={loading}>
            {loading ? (
              <>
                <Loader2 className="spinner" size={24} />
                Analyzing with AI & Threat Intel...
              </>
            ) : (
              'Check Security'
            )}
          </button>
        </form>

        {error && (
          <div className="error-message">
            <AlertCircle size={24} />
            <span>{error}</span>
          </div>
        )}

        {result && (
          <div className="result-panel">
            <div className="risk-score-container">
              <div className={`score-circle ${result.prediction.toLowerCase()}`}>
                <span className="score-value">{result.riskScore}</span>
                <span className="score-label">Risk Score</span>
              </div>

              <div className={`result-badge ${result.prediction.toLowerCase()}`}>
                {result.prediction === 'Safe' ? <ShieldCheck size={20} /> : result.prediction === 'Suspicious' ? <TriangleAlert size={20} /> : <ShieldAlert size={20} />}
                {result.prediction}
              </div>
            </div>

            <div className="result-details">
              <div className="details-header">
                <h3>Threat Analysis Breakdown</h3>
                <div className="threat-bar-container">
                  <div
                    className="threat-bar"
                    style={{
                      width: getWidth(result.riskScore),
                      background: getGradient(result.riskScore)
                    }}
                  ></div>
                </div>
              </div>

              <div className="check-grid">
                {generateChecks(result.reasons).map((check, idx) => (
                  <div className="check-item" key={idx}>
                    {check.passed ? (
                      <CheckCircle2 className="check-icon pass" size={20} />
                    ) : (
                      <XCircle className="check-icon fail" size={20} />
                    )}
                    <div className="check-content">
                      <h4>{check.label}</h4>
                      <p>{check.passed ? check.desc : 'Check failed'}</p>
                    </div>
                  </div>
                ))}
              </div>

              {/* Detailed Reasons List */}
              <div style={{ marginTop: '1.5rem', backgroundColor: 'var(--bg-color)', padding: '1rem', borderRadius: '0.5rem', border: '1px solid var(--border-color)' }}>
                <h4 style={{ fontSize: '0.9rem', marginBottom: '0.5rem', color: 'var(--text-secondary)' }}>Detailed Log:</h4>
                <ul style={{ listStylePosition: 'inside', fontSize: '0.85rem', color: 'var(--text-primary)', lineHeight: '1.5' }}>
                  {result.reasons.map((r, i) => <li key={i}>{r}</li>)}
                </ul>
              </div>
              {url.startsWith('http://') && (
                <div style={{
                  marginTop: '1rem',
                  padding: '0.5rem',
                  borderRadius: '0.5rem',
                  backgroundColor: '#2a1f1f',
                  color: '#ff6b6b',
                  fontSize: '0.85rem',
                  border: '1px solid #ff6b6b'
                }}>
                  ⚠️ This website is using HTTP (not secure)
                </div>
              )}

              <div className="whois-meta">
                <div className="meta-item">
                  <span className="meta-label">Engine Version</span>
                  <span className="meta-value"><Activity size={14} /> v3.0 (ML + Rules)</span>
                </div>
                <div className="meta-item">
                  <span className="meta-label">Scan ID</span>
                  <span className="meta-value">
                    <Hash size={14} /> {result.scanId}
                  </span>                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="recent-scans-section">
        <h3>Recent Scans</h3>

        {recentScans.length === 0 ? (
          <div className="no-scans">No recent scans available. Analyze a URL to get started.</div>
        ) : (
          <div className="recent-scans-list">
            {recentScans.map((scan, index) => (
              <div
                className="recent-scan-item"
                key={index}
                onClick={() => handleRecentClick(scan)}
                style={{ cursor: 'pointer' }}
                title="Click to view report"
              >
                <div className="scan-url">
                  <Globe className="scan-url-icon" size={18} />
                  {scan.url}
                  <span className="scan-time">{scan.time}</span>
                </div>

                <div className={`scan-result-badge ${scan.result.prediction.toLowerCase()}`}>
                  {scan.result.prediction === 'Safe' ? <ShieldCheck size={16} /> : scan.result.prediction === 'Suspicious' ? <TriangleAlert size={16} /> : <ShieldAlert size={16} />}
                  {scan.result.prediction}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
