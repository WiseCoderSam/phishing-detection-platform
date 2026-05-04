import { useState } from 'react';
import {
  Shield, ShieldAlert, ShieldCheck, Link2, Loader2, AlertCircle,
  TriangleAlert, CheckCircle2, XCircle, Globe, Activity, Hash,
  Search, ScrollText
} from 'lucide-react';
import './index.css';

/* ── helpers ─────────────────────────────────────────────────────────────── */
const toKey = (pred = '') => pred.toLowerCase();

function riskColor(score) {
  if (score <= 29) return 'var(--success)';
  if (score <= 50) return 'var(--warning)';
  return 'var(--danger)';
}

function generateChecks(reasons = []) {
  return [
    { id: 'blacklist', label: 'Safe Browsing Blacklist', passed: !reasons.some(r => r.includes('Blacklisted')),           desc: 'Not flagged by Google' },
    { id: 'ml',        label: 'ML Analysis',             passed: !reasons.some(r => r.includes('model flagged')),          desc: 'AI anomaly detection' },
    { id: 'brand',     label: 'Brand Impersonation',     passed: !reasons.some(r => r.includes('impersonation detected')), desc: 'Matches official domain' },
    { id: 'keywords',  label: 'Suspicious Keywords',     passed: !reasons.some(r => r.includes('keyword')),               desc: 'No deceptive terms' },
    { id: 'hyphens',   label: 'Domain Hyphens',          passed: !reasons.some(r => r.includes('hyphens')),               desc: 'Standard hyphen usage' },
    { id: 'subdomains',label: 'Subdomain Depth',         passed: !reasons.some(r => r.includes('subdomains')),            desc: 'Normal subdomain depth' },
  ];
}

function logClass(reason) {
  const r = reason.toLowerCase();
  if (r.includes('blacklist') || r.includes('phishing') || r.includes('high risk') || r.includes('dangerous')) return 'danger';
  if (r.includes('suspicious') || r.includes('keyword') || r.includes('impersonation') || r.includes('hyphens') || r.includes('free host')) return 'warn';
  return '';
}

/* ── Ring SVG ────────────────────────────────────────────────────────────── */
function ScoreRing({ score, pred }) {
  const r = 34;
  const circ = 2 * Math.PI * r;
  const dash = circ - (score / 100) * circ;
  const color = riskColor(score);
  return (
    <div className="score-ring">
      <svg width="80" height="80" viewBox="0 0 80 80">
        <circle cx="40" cy="40" r={r} fill="none" stroke="var(--surface-high)" strokeWidth="6" />
        <circle
          cx="40" cy="40" r={r} fill="none"
          stroke={color} strokeWidth="6"
          strokeDasharray={circ}
          strokeDashoffset={dash}
          strokeLinecap="square"
          style={{ transition: 'stroke-dashoffset 0.6s ease' }}
        />
      </svg>
      <div className={`score-ring-num ${toKey(pred)}`}>{score}</div>
    </div>
  );
}

/* ── App ─────────────────────────────────────────────────────────────────── */
export default function App() {
  const [url, setUrl]               = useState('');
  const [loading, setLoading]       = useState(false);
  const [result, setResult]         = useState(null);
  const [error, setError]           = useState('');
  const [recentScans, setRecentScans] = useState([]);

  const handleCheck = async (e) => {
    e.preventDefault();
    if (!url.trim()) return setError('URL field is required.');
    try { new URL(url.startsWith('http') ? url : 'http://' + url); }
    catch { return setError('Invalid URL — enter a valid web address.'); }

    setLoading(true); setError(''); setResult(null);

    try {
      const res = await fetch(`${import.meta.env.VITE_API_URL}/api/check-url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || 'Server error.');
      }

      const data = await res.json();
      data.scanId = Math.random().toString(36).substring(2, 10).toUpperCase();
      data.scannedUrl = url;
      setResult(data);

      setRecentScans(prev => {
        const filtered = prev.filter(s => s.url !== url);
        return [{ url, result: data, time: new Date().toLocaleTimeString() }, ...filtered].slice(0, 8);
      });
    } catch (err) {
      setResult(null);
      setError(err.message || 'Connection failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="shell">
      <div className="main">
        {/* ── Topbar ── */}
        <header className="topbar">
          <span className="topbar-title" style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--primary-container)', fontSize: '14px' }}>
            <Shield size={16} /> PhishGuard
          </span>
        </header>

        {/* ── Scrollable Content ── */}
        <div className="content">

          {/* Scanner Input Card */}
          <div className="scanner-card">
            <div className="card-header">
              <span className="card-header-title">
                <Search size={14} />
                URL Threat Analysis
              </span>
            </div>
            <div className="card-body">
              <form onSubmit={handleCheck}>
                <div className="input-row">
                  <div className="url-field">
                    <Link2 size={16} />
                    <input
                      id="url-input"
                      className="url-input"
                      type="text"
                      placeholder="Enter target URL — e.g. example.com"
                      value={url}
                      onChange={e => setUrl(e.target.value)}
                      disabled={loading}
                      autoComplete="off"
                      spellCheck="false"
                    />
                  </div>
                  <button id="scan-btn" className="scan-btn" type="submit" disabled={loading}>
                    {loading
                      ? <><Loader2 size={14} className="spinner" /> Scanning...</>
                      : <><Search size={14} /> Analyze</>
                    }
                  </button>
                </div>
              </form>

              {error && (
                <div className="error-banner">
                  <AlertCircle size={15} />
                  {error}
                </div>
              )}
            </div>
          </div>

          {/* ── Results (shown after scan) ── */}
          {result && (
            <div className="results-card">
              {/* Result Header */}
              <div className="result-header">
                <div className={`verdict-badge ${toKey(result.prediction)}`}>
                  {result.prediction === 'Safe'
                    ? <ShieldCheck size={14} />
                    : result.prediction === 'Suspicious'
                    ? <TriangleAlert size={14} />
                    : <ShieldAlert size={14} />
                  }
                  {result.prediction}
                </div>
                <div className="scan-meta">
                  <span><Hash size={10} style={{display:'inline',marginRight:4}} />{result.scanId}</span>
                  <span><Activity size={10} style={{display:'inline',marginRight:4}} />ENGINE v3.0</span>
                </div>
              </div>

              {/* Score + Threat Bar */}
              <div className="score-gauge-row">
                <div className="score-block">
                  <ScoreRing score={result.riskScore} pred={result.prediction} />
                  <div className="score-ring-label">Risk Score</div>
                </div>
                <div className="threat-bar-section">
                  <div className="threat-bar-label">Threat Level</div>
                  <div className="threat-bar-track">
                    <div
                      className="threat-bar-fill"
                      style={{
                        width: `${Math.max(5, result.riskScore)}%`,
                        background: riskColor(result.riskScore),
                      }}
                    />
                  </div>
                  <div style={{ marginTop: 10, fontSize: 12, color: 'var(--on-surface-variant)', fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>
                    {result.scannedUrl}
                  </div>

                  {/* HTTP warning inline */}
                  {url.startsWith('http://') && (
                    <div className="http-warn" style={{ margin: '12px 0 0' }}>
                      <TriangleAlert size={13} /> Insecure connection — site uses HTTP, not HTTPS
                    </div>
                  )}
                </div>
              </div>

              {/* Security Checks Grid */}
              <div className="checks-section">
                <div className="checks-section-title">Security Checks</div>
                <div className="checks-grid">
                  {generateChecks(result.reasons).map(check => (
                    <div className="check-item" key={check.id}>
                      {check.passed
                        ? <CheckCircle2 size={15} className="check-icon-pass" />
                        : <XCircle     size={15} className="check-icon-fail" />
                      }
                      <div className="check-text">
                        <h4>{check.label}</h4>
                        <p>{check.passed ? check.desc : 'Check failed'}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Analysis Log */}
              <div className="log-section">
                <div className="log-section-title">Analysis Log</div>
                <div className="log-terminal">
                  {result.reasons.map((r, i) => (
                    <div key={i} className={`log-line ${logClass(r)}`}>{r}</div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ── Recent Scans ── */}
          <div className="recent-card">
            <div className="card-header">
              <span className="card-header-title">
                <ScrollText size={14} />
                Recent Scans
              </span>
            </div>
            {recentScans.length === 0
              ? <div className="no-scans">No recent scans — analyze a URL to get started.</div>
              : (
                <div className="recent-list">
                  {recentScans.map((scan, i) => (
                    <div
                      className="recent-row"
                      key={i}
                      onClick={() => { setUrl(scan.url); setResult(scan.result); }}
                      title="Click to reload result"
                    >
                      <div className="recent-url">
                        <Globe size={13} />
                        <span>{scan.url}</span>
                        <span className="recent-time">{scan.time}</span>
                      </div>
                      <div className={`verdict-badge ${toKey(scan.result.prediction)}`} style={{ padding: '2px 8px', fontSize: '10px' }}>
                        {scan.result.prediction === 'Safe'
                          ? <ShieldCheck size={11} />
                          : scan.result.prediction === 'Suspicious'
                          ? <TriangleAlert size={11} />
                          : <ShieldAlert size={11} />
                        }
                        {scan.result.prediction}
                      </div>
                    </div>
                  ))}
                </div>
              )
            }
          </div>

        </div>{/* /content */}
      </div>{/* /main */}
    </div>
  );
}
