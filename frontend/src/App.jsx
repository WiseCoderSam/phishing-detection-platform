import { useState, useEffect, useRef } from 'react';
import {
  Shield, ShieldAlert, ShieldCheck, Link2, Loader2, AlertCircle,
  TriangleAlert, CheckCircle2, XCircle, Globe, Activity, Hash,
  Search, ScrollText, FileText
} from 'lucide-react';
import './index.css';

/* ── Particle Canvas Component ───────────────────────────────────────────── */
function ParticleCanvas() {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    let W, H, dpr;

    const resize = () => {
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      W = canvas.clientWidth;
      H = canvas.clientHeight;
      canvas.width = W * dpr;
      canvas.height = H * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };

    window.addEventListener('resize', resize);
    resize();

    const N = Math.min(72, Math.floor(W * H / 22000));
    const pts = Array.from({ length: N }, () => ({
      x: Math.random() * W,
      y: Math.random() * H,
      vx: (Math.random() - 0.5) * 0.28,
      vy: (Math.random() - 0.5) * 0.28,
      r: Math.random() * 1.6 + 0.6,
    }));

    const mouse = { x: -999, y: -999 };

    const onMove = (e) => {
      mouse.x = e.clientX;
      mouse.y = e.clientY;
    };

    window.addEventListener('mousemove', onMove);

    let animationId;
    const tick = () => {
      ctx.clearRect(0, 0, W, H);

      for (const p of pts) {
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < 0 || p.x > W) p.vx *= -1;
        if (p.y < 0 || p.y > H) p.vy *= -1;
      }

      // Draw connections
      for (let i = 0; i < pts.length; i++) {
        for (let j = i + 1; j < pts.length; j++) {
          const a = pts[i];
          const b = pts[j];
          const dx = a.x - b.x;
          const dy = a.y - b.y;
          const d2 = dx * dx + dy * dy;
          if (d2 < 130 * 130) {
            const alpha = (1 - d2 / (130 * 130)) * 0.22;
            ctx.strokeStyle = `rgba(34,211,238,${alpha})`;
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.stroke();
          }
        }
      }

      // Draw particles
      for (const p of pts) {
        const mdx = p.x - mouse.x;
        const mdy = p.y - mouse.y;
        const near = mdx * mdx + mdy * mdy < 150 * 150;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = near ? 'rgba(103,232,249,.9)' : 'rgba(34,211,238,.45)';
        ctx.fill();
      }

      animationId = requestAnimationFrame(tick);
    };

    tick();

    return () => {
      cancelAnimationFrame(animationId);
      window.removeEventListener('resize', resize);
      window.removeEventListener('mousemove', onMove);
    };
  }, []);

  return <canvas id="particle-canvas" ref={canvasRef} />;
}

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
    { id: 'ml',        label: 'ML Analysis',             passed: !reasons.some(r => r.toLowerCase().includes('highly confident')), desc: 'AI anomaly detection' },
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
  const r = 46;
  const circ = 2 * Math.PI * r;
  const dash = circ * (score / 100);
  const color = riskColor(score);
  return (
    <div className="score-ring">
      <svg width="104" height="104" viewBox="0 0 104 104" style={{ transform: 'rotate(-90deg)' }}>
        <circle cx="52" cy="52" r={r} fill="none" stroke="rgba(255,255,255,.07)" strokeWidth="7" />
        <circle
          cx="52"
          cy="52"
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="7"
          strokeLinecap="round"
          strokeDasharray={`${dash} ${circ}`}
          style={{
            filter: `drop-shadow(0 0 6px ${color})`,
            transition: 'stroke-dasharray 0.6s ease'
          }}
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
  // If no API URL is configured there's nothing to warm, so the engine is "ready" immediately.
  const [engineReady, setEngineReady] = useState(!import.meta.env.VITE_API_URL);
  const [warmSecs, setWarmSecs]     = useState(0);
  // Bumping this re-runs the warm-up effect (used when a scan reports the engine is still warming).
  const [warmKey, setWarmKey]       = useState(0);

  // Proactively wake the backend + ML service on first load and poll until both are up.
  // On Render's free tier a cold start can take ~50s, so we show a live timer and keep the
  // Analyze button disabled until the engine reports ready.
  useEffect(() => {
    const apiUrl = import.meta.env.VITE_API_URL;
    if (!apiUrl) return;   // nothing to warm — engineReady already initialised true above

    let cancelled = false;
    const started = Date.now();
    const finish = () => { if (!cancelled) { cancelled = true; setEngineReady(true); } };

    const timer = setInterval(() => {
      if (!cancelled) setWarmSecs(Math.floor((Date.now() - started) / 1000));
    }, 1000);

    // Safety net: a normal cold start finishes (~50s) well before this fires; it only exists so a
    // genuinely-down backend can't lock the UI forever. If it releases early, the backend still
    // returns an honest "warming up" 503 and the UI drops back into warm-up mode.
    const fallback = setTimeout(finish, 90000);

    const poll = async () => {
      while (!cancelled) {
        try {
          const res = await fetch(`${apiUrl}/api/health`);
          const data = await res.json().catch(() => ({}));
          // Ready when ML reports awake, OR when talking to an older backend with no `ml` field.
          if (data.ml === 'awake' || (res.ok && data.ml === undefined)) { finish(); break; }
        } catch { /* backend still cold — keep polling */ }
        await new Promise(r => setTimeout(r, 3000));
      }
    };
    poll();

    return () => { cancelled = true; clearInterval(timer); clearTimeout(fallback); };
  }, [warmKey]);

  // Drop the UI back into warm-up mode (banner + timer + disabled button) and re-run the poll.
  const restartWarmUp = () => { setEngineReady(false); setWarmSecs(0); setWarmKey(k => k + 1); };

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
        // Engine still warming up — go back into warm-up mode so the button re-enables when ready.
        if (res.status === 503 && err.warmingUp) {
          restartWarmUp();
          throw new Error(err.error || 'The analysis engine is warming up. Please try again in a moment.');
        }
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
      <ParticleCanvas />
      <div className="main">
        {/* ── Topbar ── */}
        <header className="topbar">
          <span className="topbar-title">
            <div style={{
              width: '32px',
              height: '32px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              borderRadius: '9px',
              background: 'linear-gradient(145deg,rgba(34,211,238,.22),rgba(34,211,238,.05))',
              border: '1px solid rgba(34,211,238,.35)',
              boxShadow: '0 0 18px rgba(34,211,238,.25)',
            }}>
              <Shield size={17} color="#22d3ee" strokeWidth={2} />
            </div>
            PHISHGUARD
          </span>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '7px',
            fontFamily: 'var(--font-mono)',
            fontSize: '11px',
            letterSpacing: '.14em',
            color: '#5a6b76',
            textTransform: 'uppercase',
          }}>
            <span style={{
              width: '7px',
              height: '7px',
              borderRadius: '50%',
              background: '#34d399',
              boxShadow: '0 0 8px #34d399',
              animation: 'pg-glow 2.4s ease-in-out infinite',
            }} />
            ENGINE V3.0 · ONLINE
          </div>
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
              {!engineReady && (
                <div
                  className="warmup-banner"
                  style={{
                    padding: '12px 14px', marginBottom: 12, borderRadius: 8,
                    color: 'var(--warning)',
                    background: 'color-mix(in srgb, var(--warning) 12%, transparent)',
                    border: '1px solid color-mix(in srgb, var(--warning) 35%, transparent)',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                    <span style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, fontWeight: 600 }}>
                      <Loader2 size={15} className="spinner" />
                      Warming up the backend…
                    </span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 13, fontWeight: 700, fontVariantNumeric: 'tabular-nums' }}>
                      {warmSecs}s
                    </span>
                  </div>
                  <div style={{ fontSize: 11.5, opacity: 0.85, marginTop: 5 }}>
                    First scan after inactivity can take up to ~60s on the free tier. Link testing unlocks automatically once the engine is ready.
                  </div>
                  <div style={{ height: 4, borderRadius: 4, marginTop: 9, background: 'color-mix(in srgb, var(--warning) 20%, transparent)', overflow: 'hidden' }}>
                    <div style={{ height: '100%', width: `${Math.min(100, (warmSecs / 60) * 100)}%`, background: 'var(--warning)', transition: 'width 1s linear' }} />
                  </div>
                </div>
              )}
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
                      disabled={loading || !engineReady}
                      autoComplete="off"
                      spellCheck="false"
                    />
                  </div>
                  <button id="scan-btn" className="scan-btn" type="submit" disabled={loading || !engineReady}>
                    {!engineReady
                      ? <><Loader2 size={14} className="spinner" /> Warming up…</>
                      : loading
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
                        filter: `drop-shadow(0 0 12px ${riskColor(result.riskScore)})`,
                      }}
                    />
                  </div>
                  <div style={{ marginTop: 14, fontSize: 13, color: 'var(--on-surface-muted)', fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>
                    {result.scannedUrl}
                  </div>

                  {/* HTTP warning inline */}
                  {url.startsWith('http://') && (
                    <div className="http-warn">
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
                      <div className="check-item-icon" style={{
                        background: check.passed
                          ? 'rgba(52,211,153,.12)'
                          : 'rgba(244,63,94,.12)',
                      }}>
                        {check.passed
                          ? <CheckCircle2 size={13} className="check-icon-pass" />
                          : <XCircle size={13} className="check-icon-fail" />
                        }
                      </div>
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
                  {result.reasons.map((r, i) => {
                    const cls = logClass(r);
                    const marker = cls === 'warn' ? '!' : cls === 'danger' ? '!' : '>';
                    const markerColor = cls === 'warn' ? '#f59e0b' : cls === 'danger' ? '#f43f5e' : '#22d3ee';
                    return (
                      <div key={i} className="log-line">
                        <span className="log-line-marker" style={{ color: markerColor }}>{marker}</span>
                        <span>{r}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}

          {/* ── Recent Scans ── */}
          <div className="recent-card">
            <div className="card-header">
              <span className="card-header-title">
                <ScrollText size={15} />
                RECENT SCANS
              </span>
              {recentScans.length > 0 && (
                <span style={{
                  marginLeft: 'auto',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '11px',
                  color: '#5a6b76',
                  textTransform: 'uppercase',
                }}>
                  {recentScans.length} TOTAL
                </span>
              )}
            </div>
            {recentScans.length === 0
              ? (
                <div className="no-scans">
                  <div className="no-scans-icon">
                    <FileText size={22} />
                  </div>
                  <div className="no-scans-text">No recent scans — analyze a URL to get started.</div>
                </div>
              )
              : (
                <div className="recent-list">
                  {recentScans.map((scan, i) => (
                    <div
                      className="recent-row"
                      key={i}
                      onClick={() => { setUrl(scan.url); setResult(scan.result); }}
                      title="Click to reload result"
                    >
                      <Globe size={15} style={{ color: '#546570', flexShrink: 0 }} />
                      <span style={{ flex: 1, fontFamily: 'var(--font-mono)', fontSize: '13px', color: 'var(--on-surface-muted)', wordBreak: 'break-all' }}>
                        {scan.url}
                      </span>
                      <span className="recent-time">{scan.time}</span>
                      <div className={`verdict-badge ${toKey(scan.result.prediction)}`} style={{ padding: '4px 10px', fontSize: '11px' }}>
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
